# PeerGrid Deployment & Domain Configuration Guide

This guide describes how to deploy the static PWA frontend and the Python WebSocket relay server, and how to link your custom domains (`peergrid.app` and `peergrid.in`).

---

## 1. Architecture Overview

```
                      [ User's Browser (PWA) ]
                       /                  \
             HTTPS    /                    \    WSS
             (Static)/                      \   (WebSockets)
                    v                        v
          [ PeerGrid PWA ]           [ Python Relay Server ]
       (Vercel / Cloudflare Pages)     (Render / Railway VPS)
           peergrid.app                 api.peergrid.app
```

---

## 2. Deploying the PWA Frontend (peergrid.app / peergrid.in)

Since the PeerGrid client is a static PWA (HTML, CSS, JavaScript, WebAssembly), it can be hosted for free on a global CDN.

### Step 2.1: Host on Cloudflare Pages or Vercel
1. Initialize a Git repository in your codebase and push it to GitHub:
   ```bash
   git init
   git add .
   git commit -m "Initialize PeerGrid"
   # Create a repository on GitHub and push
   git remote add origin git@github.com:yourusername/peergrid.git
   git branch -M main
   git push -u origin main
   ```
2. Log in to [Cloudflare Dashboard](https://dash.cloudflare.com/) or [Vercel](https://vercel.com).
3. Select **Create Project** -> **Import from GitHub** -> Select your repository.
4. Set the build configurations:
   * **Framework Preset**: None (Static site)
   * **Build command**: Leave empty (no build command needed)
   * **Output Directory**: `client` (This ensures only the client files are exposed to the web)
5. Click **Deploy**. Your static app is now online on a default subdomain (e.g., `peergrid.pages.dev` or `peergrid.vercel.app`).

### Step 2.2: Link Custom Domains (`peergrid.app` / `peergrid.in`)
1. In Vercel or Cloudflare Pages, go to **Settings** -> **Custom Domains**.
2. Click **Add Domain** and enter:
   * `peergrid.app`
   * `peergrid.in` (and configure redirects from `.in` to `.app` if desired).
3. Navigate to your domain registrar (GoDaddy, Namecheap, Google Domains, or Cloudflare DNS) and add the CNAME record:

| Type | Name | Value | TTL |
| :--- | :--- | :--- | :--- |
| **CNAME** | `@` | `peergrid.pages.dev` (or Vercel alias) | Auto |
| **CNAME** | `www` | `peergrid.app` (for redirection) | Auto |

*Vercel or Cloudflare will automatically generate SSL certificates for HTTPS secure loading.*

---

## 3. Deploying the Python Relay Backend (api.peergrid.app)

The Python relay uses `websockets` and an SQLite database to store E2EE mailbox packets. It must run 24/7 on a persistent backend.

### Step 3.1: Host on Render or Railway
1. Log in to [Railway](https://railway.app/) or [Render](https://render.com/).
2. Select **New Web Service** -> **Import from GitHub** -> Select your repository.
3. Configure the runtime settings:
   * **Environment**: Python (Python 3.10+)
   * **Build Command**: `pip install -r relay/requirements.txt`
   * **Start Command**: `python relay/relay.py`
4. Expose the port: Set `PORT` environment variable to `8765` (or check what port is used by Render/Railway).
5. Click **Deploy**. You will receive a backend HTTPS URL (e.g., `peergrid-relay.up.railway.app` or `peergrid-relay.onrender.com`).

### Step 3.2: Link Custom Subdomain (`api.peergrid.app`)
1. In your Render/Railway service dashboard, go to **Custom Domains** -> **Add Custom Domain**.
2. Enter `api.peergrid.app` (or `api.peergrid.in`).
3. Add the corresponding DNS record at your domain registrar:

| Type | Name | Value | TTL |
| :--- | :--- | :--- | :--- |
| **CNAME** | `api` | `peergrid-relay.up.railway.app` (or Render alias) | Auto |

---

## 4. Double-Checking Configurations
Once deployed:
1. Open `https://peergrid.app` in your browser.
2. The client will load over HTTPS, automatically launch, detect it is not running on localhost, and establish a secure WebSocket channel to `wss://api.peergrid.app`.
3. Check the developer console: It should read `[Relay Node WS Connected: Direct node communication active]` indicating a successful secure WebSocket (WSS) link!
