FROM python:3.10-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1

RUN mkdir -p /data

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt -i https://mirrors.aliyun.com/pypi/simple/

COPY github_env_scanner.py /app/

CMD ["python", "-u", "github_env_scanner.py"]