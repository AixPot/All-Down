FROM python:3.11-slim

# 安装系统级依赖
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app .

EXPOSE 3469
CMD ["flask", "run", "--host=0.0.0.0", "--port=3469"]