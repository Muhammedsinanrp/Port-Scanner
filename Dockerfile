# Production Dockerfile for AegisScan on Cloud VPS
FROM python:3.11-slim

# Install system dependencies & official Nmap
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    iputils-ping \
    dnsutils \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Copy application code
COPY . .

ENV PORT=5000
EXPOSE 5000

# Start using production Gunicorn WSGI server (supports dynamic $PORT on free cloud hosts)
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 3 --threads 4 --timeout 180 web_app:app"]

