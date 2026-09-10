# Deploying Vulture AI on Render (`render.com`)

This guide explains how to deploy **Vulture AI** (FastAPI Backend + React Vite Tailwind Frontend + Nmap Scanner) on [Render](https://render.com).

---

## Method 1: One-Click Blueprint Deployment (Recommended)

Render Blueprints use the [`render.yaml`](./render.yaml) file in the root of the repository to provision and configure the service automatically.

1. **Push your repository** to GitHub (already synced to `https://github.com/damanknows/Vulture-AI`).
2. Log in to [Render Dashboard](https://dashboard.render.com).
3. Click **New +** → **Blueprint**.
4. Select your **`damanknows/Vulture-AI`** repository.
5. Render will automatically read `render.yaml` and configure the **`vulture-ai`** Web Service.
6. (Optional) Set the `NVD_API_KEY` secret variable if you have one.
7. Click **Apply**.
8. Once built, your app will be live at `https://vulture-ai.onrender.com`!

---

## Method 2: Manual Web Service Deployment (Docker)

If you prefer to configure the Web Service manually:

1. In Render Dashboard, click **New +** → **Web Service**.
2. Connect your GitHub repository: `https://github.com/damanknows/Vulture-AI`.
3. Configure the following settings:
   - **Name:** `vulture-ai`
   - **Language / Runtime:** `Docker`
   - **Dockerfile Path:** `./Dockerfile`
   - **Region:** Any (e.g. `Oregon (US West)` or `Frankfurt (EU)`)
   - **Instance Type:** `Free`
4. In **Environment Variables**, add:
   | Key | Value | Notes |
   |---|---|---|
   | `PORT` | `10000` | Render sets this automatically |
   | `HOST` | `0.0.0.0` | Listen on all interfaces |
   | `CORS_ORIGINS` | `*` | Or your custom domain |
   | `DB_URL` | `sqlite:////app/vulmap.db` | Local SQLite database |
   | `ALLOWED_TARGETS` | `127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16` | Allowlisted scan targets |
   | `NVD_API_KEY` | *(optional)* | NIST NVD API Key |
5. Click **Create Web Service**.

---

## Live Endpoints on Render

Once deployed, your Render URL provides:
- **`https://<your-app>.onrender.com/`** — High-Conversion Landing Page
- **`https://<your-app>.onrender.com/app`** — Live Vulnerability Scanner Console
- **`https://<your-app>.onrender.com/api/*`** — FastAPI Backend REST Endpoints
- **`https://<your-app>.onrender.com/docs`** — Interactive Swagger / OpenAPI Documentation
- **`https://<your-app>.onrender.com/health`** — Health check endpoint (`{"status": "ok"}`)
