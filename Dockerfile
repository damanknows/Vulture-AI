# ── Stage 1: Build React Frontend ─────────────────────────────────────────
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend

COPY vulmap-pro/frontend/package*.json ./
RUN npm ci --prefer-offline --no-audit || npm install --no-audit

COPY vulmap-pro/frontend/ ./
RUN npm run build

# ── Stage 2: Python Backend with Nmap ──────────────────────────────────────
FROM python:3.12-slim

# Install system dependencies & Nmap scanner binary
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python requirements
COPY vulmap-pro/backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# Copy backend & scanner code
COPY vulmap-pro/backend /app/backend
COPY vulmap-pro/scanner /app/scanner

# Copy built frontend assets for unified serving
COPY --from=frontend-builder /app/frontend/dist /app/frontend/dist

ENV PYTHONUNBUFFERED=1
ENV PORT=8000
ENV HOST=0.0.0.0

EXPOSE 8000

CMD ["sh", "-c", "uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
