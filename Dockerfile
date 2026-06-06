# 使用轻量级的 Python 基础镜像
FROM python:3.10-slim

# 设置工作目录
WORKDIR /app

# 设置环境变量，防止 Python 缓冲 stdout 和 stderr
ENV PYTHONUNBUFFERED=1

# 持久化去重文件（挂载此目录可在容器重启后保留历史 Key，防止重复告警）
ENV SEEN_KEYS_FILE=/data/seen_keys.json
RUN mkdir -p /data

# 将当前目录下的 requirements.txt 复制到容器中
COPY requirements.txt /app/

# 安装依赖，使用阿里云镜像源加速
RUN pip install --no-cache-dir -r requirements.txt -i https://mirrors.aliyun.com/pypi/simple/

# 将脚本复制到容器中
COPY github_env_scanner.py /app/

# 设置默认启动命令
CMD ["python", "-u", "github_env_scanner.py"]