FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY app/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app /app/app

RUN useradd -r -u 10002 -g root gdsagent && \
    mkdir -p /var/lib/labshock-gds-agent && \
    chown -R gdsagent:root /var/lib/labshock-gds-agent /app

USER gdsagent

CMD ["python", "-m", "app.main"]
