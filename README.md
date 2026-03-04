# 📋 Sophos Central Device Export Tool

A lightweight, self-hosted web tool that connects to your **Sophos Central Partner** account, lets you select any managed tenant/customer, and downloads a **CSV or PDF** of all their endpoints — complete with health status, OS details, IP addresses, tamper protection state, and more.

---

## What's Exported

Each row represents one Sophos-managed endpoint:

| Column | Description |
|---|---|
| Hostname | Device hostname |
| Type | computer / server / mobile |
| Customer | Tenant/customer name |
| Group | Sophos group the endpoint belongs to |
| Endpoint ID | Internal Sophos UUID |
| IP Address(es) | All reported IPv4 addresses |
| MAC Address(es) | All reported MAC addresses |
| OS Name | Operating system name |
| OS Version | Major OS version |
| OS Platform | windows / macOS / linux |
| OS Build | Specific build number |
| Last OS Update | Date of last OS update applied |
| Health (Overall) | good / bad / suspicious |
| Health (Threats) | Threat detection status |
| Health (Services) | Sophos services status |
| Tamper Protection | Enabled / Disabled |
| Sophos Version | Intercept X / Endpoint agent version |
| Serial Number | Hardware serial (Mac endpoints) |
| Last Seen | Last Sophos check-in timestamp |
| Registered At | When device was enrolled |
| Cloud Provider | AWS / Azure / GCP if applicable |
| Data Region | Sophos data region (eu01, us01, etc.) |

> CSV is UTF-8 with BOM for clean Excel compatibility on Windows.

---

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/)
- A Sophos Central **Partner** account
- A **Service Principal** (Client ID + Client Secret) — see below

---

## Creating a Sophos API Service Principal

1. Log in to **Sophos Central Partner**
2. Go to **Settings → API Credentials Management**
3. Click **Add Credential**
4. Give it a name (e.g. `device-export-tool`)
5. Assign the **Service Principal Read-Only** role
6. Copy the **Client ID** and **Client Secret** immediately — the secret is shown once only

> ⚠️ Never commit your Client ID or Client Secret to source control.

---

## Quick Start

### 1. Pull the image

```bash
docker pull samuelstreets/sophos-device-export:latest
```

### 2. Set your API credentials

Open `docker-compose.yml` and replace the placeholders:

```yaml
environment:
  - SOPHOS_CLIENT_ID=your_client_id_here
  - SOPHOS_CLIENT_SECRET=your_client_secret_here
```

### 3. Run

```bash
docker compose up -d
```

### 4. Open the tool

Navigate to [http://localhost:8082](http://localhost:8082)

- Tenants load automatically on page open
- Search/filter tenants by name
- Click a tenant to select it
- Choose columns or use a preset
- Click **Download CSV** or **Download PDF**

---

## Configuration

| Variable | Required | Description |
|---|---|---|
| `SOPHOS_CLIENT_ID` | ✅ Yes | Your Sophos Partner API client ID |
| `SOPHOS_CLIENT_SECRET` | ✅ Yes | Your Sophos Partner API client secret |
| `PYTHONUNBUFFERED` | No | Set to `1` for real-time container logs |

Port is mapped to `8082` by default (to avoid conflicts with the N-able export on `8081` and Emerald Monitor on `8080`). Change in `docker-compose.yml` if needed.

---

## Column Presets

| Preset | Columns Included |
|---|---|
| **Essential** | Hostname, Type, Customer, IP, OS, Version, Health, Last Seen |
| **Security** | Hostname, Customer, all Health fields, Tamper Protection, Agent Version |
| **Network** | Hostname, Customer, IP, MAC, OS Platform, Data Region |
| **Full** | All 22 columns |

---

## How It Works

1. On page load, the backend authenticates via OAuth2 with `id.sophos.com` using your Client ID and Secret, then calls `/whoami/v1` to discover the Partner UUID
2. It fetches all managed tenants from `/partner/v1/tenants` (paginated, cached 5 minutes)
3. When you export, the backend calls `/endpoint/v1/endpoints?view=full` on each tenant's regional API host and streams the result as CSV or PDF
4. The "Export All" feature iterates every tenant sequentially with a small delay to respect Sophos rate limits

---

## Troubleshooting

**Tenant list won't load**
Check container logs: `docker logs sophos-export`

**AUTH FAILED in logs**
Your Client Secret may have expired (Sophos credentials have an expiry date). Create a new one in Sophos Central Partner and update `docker-compose.yml`:
```bash
docker compose down && docker compose up -d
```

**"not a partner account" error**
Your service principal was created as a tenant-level credential. You need a Partner-level credential — create it from the Sophos Central **Partner** portal, not from a customer tenant.

**Some endpoints missing**
Certain tenant API calls may return 403 if the service principal doesn't have access. These tenants are skipped with a warning in the logs.

**Serial numbers show N/A**
Sophos only reports serial numbers for macOS endpoints; Windows/Linux report N/A — this is a Sophos API limitation.

---

## Project Structure

| File | Purpose |
|---|---|
| `app.py` | OAuth2 auth + Sophos API proxy + CSV/PDF generator + HTTP server |
| `index.html` | Frontend UI (tenant search + column picker + download) |
| `Dockerfile` | Container image (Python 3.9 slim) |
| `docker-compose.yml` | Service definition |
| `.github/workflows/docker-build.yml` | CI/CD — builds `linux/amd64` + `linux/arm64` and pushes to Docker Hub |
