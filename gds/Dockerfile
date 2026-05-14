FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    nginx \
    wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY app/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app /app/app
COPY nginx /app/nginx
COPY docker-entrypoint.sh /app/docker-entrypoint.sh

RUN chmod +x /app/docker-entrypoint.sh && \
    useradd -r -u 10001 -g root gds && \
    mkdir -p /var/lib/labshock-gds && \
    chown -R gds:root /var/lib/labshock-gds /app

EXPOSE 8081 8443 58810

ENTRYPOINT ["/app/docker-entrypoint.sh"]
