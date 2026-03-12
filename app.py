import os
import sys
import requests
import json
import time
import threading
import traceback
import csv
import io
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

# ── ReportLab PDF ─────────────────────────────────────────────────────────────
try:
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import (SimpleDocTemplate, Table, TableStyle,
                                     Paragraph, Spacer, HRFlowable)
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    REPORTLAB_OK = True
except ImportError:
    REPORTLAB_OK = False

# ── Configuration ─────────────────────────────────────────────────────────────
SOPHOS_CLIENT_ID     = os.environ.get("SOPHOS_CLIENT_ID", "")
SOPHOS_CLIENT_SECRET = os.environ.get("SOPHOS_CLIENT_SECRET", "")
SOPHOS_AUTH_URL      = "https://id.sophos.com/api/v2/oauth2/token"
SOPHOS_WHOAMI_URL    = "https://api.central.sophos.com/whoami/v1"
SOPHOS_GLOBAL_URL    = "https://api.central.sophos.com"

CACHE_FILE   = "data/cache.json"
CACHE_TTL    = 86400        # 24 hours
REQUEST_DELAY = 0.1         # small delay between per-tenant calls

os.makedirs("data", exist_ok=True)

cache_lock   = threading.Lock()
token_lock   = threading.Lock()
_cached_token = {"access_token": None, "expires_at": 0}

# ── All available columns ─────────────────────────────────────────────────────
ALL_COLUMNS = [
    # (key, label, group)
    ("hostname",           "Hostname",              "Identity"),
    ("endpoint_type",      "Type",                  "Identity"),
    ("customer",           "Customer",              "Identity"),
    ("group_name",         "Group",                 "Identity"),
    ("endpoint_id",        "Endpoint ID",           "Identity"),
    ("ip_addresses",       "IP Address(es)",        "Network"),
    ("mac_addresses",      "MAC Address(es)",       "Network"),
    ("os_name",            "OS Name",               "Operating System"),
    ("os_version",         "OS Version",            "Operating System"),
    ("os_platform",        "OS Platform",           "Operating System"),
    ("os_build",           "OS Build",              "Operating System"),
    ("last_os_update",     "Last OS Update",        "Operating System"),
    ("health_overall",     "Health (Overall)",      "Security"),
    ("health_threats",     "Health (Threats)",      "Security"),
    ("health_services",    "Health (Services)",     "Security"),
    ("tamper_protection",  "Tamper Protection",     "Security"),
    ("endpoint_version",   "Sophos Version",        "Security"),
    ("serial_number",      "Serial Number",         "Hardware"),
    ("last_seen",          "Last Seen",             "Activity"),
    ("registered_at",      "Registered At",         "Activity"),
    ("cloud_provider",     "Cloud Provider",        "Activity"),
    ("data_region",        "Data Region",           "Activity"),
]

COLUMN_KEYS   = [c[0] for c in ALL_COLUMNS]
COLUMN_LABELS = {c[0]: c[1] for c in ALL_COLUMNS}

DEFAULT_COLUMNS = [
    "hostname", "endpoint_type", "customer", "group_name",
    "ip_addresses", "os_name", "os_version",
    "health_overall", "health_threats", "health_services",
    "tamper_protection", "last_seen",
]


def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)


# ── OAuth2 Authentication ─────────────────────────────────────────────────────

def get_access_token():
    """Return a valid OAuth2 access token, refreshing if expired."""
    with token_lock:
        now = time.time()
        if _cached_token["access_token"] and now < _cached_token["expires_at"] - 30:
            return _cached_token["access_token"]

        if not SOPHOS_CLIENT_ID or not SOPHOS_CLIENT_SECRET:
            raise Exception("SOPHOS_CLIENT_ID and SOPHOS_CLIENT_SECRET environment variables are required.")

        resp = requests.post(
            SOPHOS_AUTH_URL,
            data={
                "grant_type":    "client_credentials",
                "client_id":     SOPHOS_CLIENT_ID,
                "client_secret": SOPHOS_CLIENT_SECRET,
                "scope":         "token",
            },
            timeout=30,
        )
        if resp.status_code != 200:
            raise Exception(f"AUTH FAILED: {resp.status_code} {resp.text[:300]}")

        data = resp.json()
        _cached_token["access_token"] = data["access_token"]
        _cached_token["expires_at"]   = now + data.get("expires_in", 3600)
        log("Obtained fresh Sophos access token.")
        return _cached_token["access_token"]


def get_partner_id(token):
    """Call /whoami/v1 to get our partner UUID."""
    resp = requests.get(
        SOPHOS_WHOAMI_URL,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("idType") != "partner":
        raise Exception(f"This credential is not a partner account (idType={data.get('idType')}). "
                        "Use a Partner-level service principal.")
    return data["id"]


# ── Tenant (customer) listing ─────────────────────────────────────────────────

def fetch_all_tenants(token, partner_id):
    """Fetch every tenant page from the Partner API."""
    tenants = []
    page    = 1
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Partner-ID":  partner_id,
        "Accept":        "application/json",
    }
    while True:
        params = {"pageSize": 100}
        if page == 1:
            params["pageTotal"] = "true"
        else:
            params["page"] = page

        resp = requests.get(
            f"{SOPHOS_GLOBAL_URL}/partner/v1/tenants",
            headers=headers, params=params, timeout=30,
        )
        resp.raise_for_status()
        body = resp.json()
        tenants.extend(body.get("items", []))

        pages_info = body.get("pages", {})
        total_pages = pages_info.get("total", 1)
        if page >= total_pages:
            break
        page += 1

    return tenants


def get_tenants_list(force=False):
    """Return cached or freshly fetched tenant list."""
    with cache_lock:
        if not force and os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, "r") as f:
                    cached = json.load(f)
                if time.time() - cached.get("fetched_at", 0) < CACHE_TTL:
                    return cached["tenants"]
            except Exception:
                pass

    log("Fetching tenant list from Sophos Partner API...")
    token      = get_access_token()
    partner_id = get_partner_id(token)
    tenants    = fetch_all_tenants(token, partner_id)

    # Sort by name; store essential fields
    tenants_slim = sorted(
        [{"id": t["id"], "name": t["name"], "apiHost": t["apiHost"],
          "dataRegion": t.get("dataRegion", ""), "billingType": t.get("billingType", "")}
         for t in tenants],
        key=lambda x: x["name"].lower(),
    )

    with cache_lock:
        with open(CACHE_FILE, "w") as f:
            json.dump({"fetched_at": time.time(), "tenants": tenants_slim, "partner_id": partner_id}, f)

    log(f"Found {len(tenants_slim)} tenants.")
    return tenants_slim


def get_tenant_by_name(name):
    tenants = get_tenants_list()
    for t in tenants:
        if t["name"] == name:
            return t
    return None


def get_partner_id_cached():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r") as f:
                return json.load(f).get("partner_id")
        except Exception:
            pass
    token = get_access_token()
    return get_partner_id(token)


# ── Endpoint fetching ─────────────────────────────────────────────────────────

def fetch_tenant_endpoints(tenant, token):
    """Fetch all endpoints for a single tenant (handles pagination)."""
    endpoints = []
    api_host  = tenant["apiHost"]
    tenant_id = tenant["id"]
    headers   = {
        "Authorization": f"Bearer {token}",
        "X-Tenant-ID":   tenant_id,
        "Accept":        "application/json",
    }
    url = f"{api_host}/endpoint/v1/endpoints"
    params = {"pageSize": 500, "view": "full"}

    while url:
        resp = requests.get(url, headers=headers, params=params, timeout=60)
        if resp.status_code == 403:
            log(f"  403 Forbidden for tenant {tenant['name']} — skipping")
            return []
        resp.raise_for_status()
        body = resp.json()
        items = body.get("items", [])
        for item in items:
            item["_tenant_name"] = tenant["name"]
            item["_data_region"] = tenant.get("dataRegion", "")
        endpoints.extend(items)

        next_key = body.get("pages", {}).get("nextKey")
        if next_key:
            url    = f"{api_host}/endpoint/v1/endpoints"
            params = {"pageFromKey": next_key, "pageSize": 500, "view": "full"}
        else:
            url = None

    return endpoints


# ── Field extraction ──────────────────────────────────────────────────────────

def safe(val, fallback="N/A"):
    if val is None or val == "":
        return fallback
    s = str(val).strip()
    return s if s else fallback


def fmt_dt(raw):
    """Parse ISO datetime and return dd/mm/yyyy HH:MM."""
    if not raw:
        return "N/A"
    try:
        return datetime.strptime(raw[:19], "%Y-%m-%dT%H:%M:%S").strftime("%d/%m/%Y %H:%M")
    except Exception:
        return safe(raw)


def extract_fields(ep):
    """Extract all displayable fields from a Sophos endpoint object."""
    os_info   = ep.get("os", {}) or {}
    health    = ep.get("health", {}) or {}
    threats   = health.get("threats", {}) or {}
    services  = health.get("services", {}) or {}
    tamper    = ep.get("tamperProtectionEnabled")
    ips       = ep.get("ipv4Addresses", []) or []
    macs      = ep.get("macAddresses", []) or []
    assigned  = ep.get("assignedProducts", []) or []
    cloud     = ep.get("cloud", {}) or {}

    # Find Intercept X / Endpoint version
    ep_version = "N/A"
    for prod in assigned:
        if prod.get("code") in ("endpointProtection", "interceptX", "interceptXForServer"):
            ep_version = safe(prod.get("version"))
            break

    return {
        "hostname":          safe(ep.get("hostname")),
        "endpoint_type":     safe(ep.get("type")),
        "customer":          safe(ep.get("_tenant_name")),
        "group_name":        safe(ep.get("groupName")),
        "endpoint_id":       safe(ep.get("id")),
        "ip_addresses":      ", ".join(ips) if ips else "N/A",
        "mac_addresses":     ", ".join(macs) if macs else "N/A",
        "os_name":           safe(os_info.get("name")),
        "os_version":        safe(os_info.get("majorVersion")),
        "os_platform":       safe(os_info.get("platform")),
        "os_build":          safe(os_info.get("build")),
        "last_os_update":    fmt_dt(os_info.get("lastUpdatedAt")),
        "health_overall":    safe(health.get("overall")),
        "health_threats":    safe(threats.get("status")),
        "health_services":   safe(services.get("status")),
        "tamper_protection": "Enabled" if tamper is True else ("Disabled" if tamper is False else "N/A"),
        "endpoint_version":  ep_version,
        "serial_number":     safe(ep.get("serialNumber")),
        "last_seen":         fmt_dt(ep.get("lastSeenAt")),
        "registered_at":     fmt_dt(ep.get("registeredAt")),
        "cloud_provider":    safe(cloud.get("provider")),
        "data_region":       safe(ep.get("_data_region")),
    }


# ── Data fetch helpers ────────────────────────────────────────────────────────

def fetch_customer_rows(customer_name):
    """Fetch all endpoints for a single named tenant."""
    tenant = get_tenant_by_name(customer_name)
    if not tenant:
        raise Exception(f"Customer '{customer_name}' not found in tenant list.")
    token = get_access_token()
    endpoints = fetch_tenant_endpoints(tenant, token)
    log(f"  {len(endpoints)} endpoints for {customer_name}")
    return [extract_fields(ep) for ep in endpoints]


def fetch_all_customer_rows():
    """Fetch all endpoints across all tenants."""
    tenants = get_tenants_list()
    token   = get_access_token()
    all_rows = []
    for i, tenant in enumerate(tenants):
        log(f"  [{i+1}/{len(tenants)}] Fetching {tenant['name']}...")
        try:
            endpoints = fetch_tenant_endpoints(tenant, token)
            all_rows.extend([extract_fields(ep) for ep in endpoints])
        except Exception as e:
            log(f"  Error fetching {tenant['name']}: {e}")
        if i > 0:
            time.sleep(REQUEST_DELAY)
    log(f"  Total endpoints across all customers: {len(all_rows)}")
    return all_rows


# ── CSV export ────────────────────────────────────────────────────────────────

def generate_csv(rows, selected_columns):
    headers = [COLUMN_LABELS[k] for k in selected_columns if k in COLUMN_LABELS]
    output  = io.StringIO()
    writer  = csv.writer(output)
    writer.writerow(headers)
    for row in rows:
        writer.writerow([row.get(k, "N/A") for k in selected_columns])
    return output.getvalue().encode("utf-8-sig")


# ── PDF export ────────────────────────────────────────────────────────────────

PDF_WHITE  = colors.white
PDF_BLACK  = colors.HexColor("#111111")
PDF_ACCENT = colors.HexColor("#0066cc")   # Sophos blue
PDF_HDR_BG = colors.HexColor("#0066cc")
PDF_ROW_A  = colors.white
PDF_ROW_B  = colors.HexColor("#f0f5fb")
PDF_BORDER = colors.HexColor("#c5d4e8")
PDF_MUTED  = colors.HexColor("#5a7080")
PDF_MID    = PDF_HDR_BG

LANDSCAPE_THRESHOLD = 7

# Health status colour mapping for PDF cells
HEALTH_COLOURS = {
    "good":    colors.HexColor("#1a9e5c"),
    "bad":     colors.HexColor("#d93f3f"),
    "suspicious": colors.HexColor("#e07b00"),
    "unknown": colors.HexColor("#7a8898"),
}


def generate_pdf(rows, selected_columns, customer_name):
    if not REPORTLAB_OK:
        raise Exception("ReportLab not installed — PDF generation unavailable.")

    buf      = io.BytesIO()
    use_land = len(selected_columns) > LANDSCAPE_THRESHOLD
    page_sz  = landscape(A4) if use_land else A4
    W, H     = page_sz
    margin   = 18 * mm

    doc = SimpleDocTemplate(
        buf, pagesize=page_sz,
        leftMargin=margin, rightMargin=margin,
        topMargin=22 * mm, bottomMargin=18 * mm,
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle("Title", fontName="Helvetica-Bold", fontSize=18,
                                 textColor=PDF_BLACK, spaceAfter=10)
    cell_style  = ParagraphStyle("Cell", fontName="Helvetica", fontSize=7,
                                 textColor=PDF_BLACK, leading=9, wordWrap="LTR")
    cell_bold   = ParagraphStyle("CellBold", fontName="Helvetica-Bold", fontSize=7,
                                 textColor=PDF_BLACK, leading=9)
    na_style    = ParagraphStyle("NA", fontName="Helvetica", fontSize=7,
                                 textColor=PDF_MUTED, leading=9)

    story = []

    story.append(Paragraph("EMERALD", ParagraphStyle(
        "Brand", fontName="Helvetica-Bold", fontSize=8,
        textColor=PDF_ACCENT, letterSpacing=4, spaceAfter=4,
    )))
    story.append(Paragraph("Sophos Endpoint Report", title_style))
    story.append(Paragraph(
        f"Customer: <b>{customer_name}</b> &nbsp;·&nbsp; "
        f"Generated: {datetime.now().strftime('%d %B %Y at %H:%M')} &nbsp;·&nbsp; "
        f"{len(rows)} endpoint{'s' if len(rows) != 1 else ''} &nbsp;·&nbsp; "
        f"{len(selected_columns)} column{'s' if len(selected_columns) != 1 else ''}",
        ParagraphStyle("Meta", fontName="Helvetica", fontSize=8,
                       textColor=PDF_MUTED, spaceAfter=6),
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=PDF_ACCENT,
                             spaceAfter=10, spaceBefore=0))

    if not rows:
        story.append(Paragraph("No endpoints found for this customer.", cell_style))
        doc.build(story, onFirstPage=_pdf_bg, onLaterPages=_pdf_bg)
        return buf.getvalue()

    usable_w = W - 2 * margin
    weight_map = {
        "hostname":        2.2, "endpoint_type": 1.2, "customer":      2.0,
        "group_name":      1.8, "ip_addresses":  2.0, "mac_addresses": 2.0,
        "os_name":         2.2, "os_version":    1.2, "endpoint_version": 1.4,
        "health_overall":  1.2, "health_threats":1.2, "health_services":  1.2,
        "last_seen":       1.6, "registered_at": 1.6, "serial_number": 1.6,
    }
    weights    = [weight_map.get(k, 1.2) for k in selected_columns]
    col_widths = [usable_w * (w / sum(weights)) for w in weights]

    header_row = [
        Paragraph(COLUMN_LABELS[k].upper(), ParagraphStyle(
            "Hdr", fontName="Helvetica-Bold", fontSize=6.5,
            textColor=PDF_WHITE, leading=8, letterSpacing=0.4,
        ))
        for k in selected_columns
    ]
    table_data = [header_row]

    for row in rows:
        table_row = []
        for k in selected_columns:
            val = row.get(k, "N/A")
            if val == "N/A" or val == "" or val is None:
                p = Paragraph("—", na_style)
            elif k == "hostname":
                p = Paragraph(str(val), cell_bold)
            else:
                p = Paragraph(str(val), cell_style)
            table_row.append(p)
        table_data.append(table_row)

    n_rows = len(table_data)
    style_cmds = [
        ("BACKGROUND",    (0, 0), (-1, 0),  PDF_MID),
        ("LINEBELOW",     (0, 0), (-1, 0),  1.5, PDF_ACCENT),
        *[("BACKGROUND",  (0, i), (-1, i), PDF_ROW_A if i % 2 == 1 else PDF_ROW_B)
          for i in range(1, n_rows)],
        ("LINEBELOW",     (0, 1), (-1, -1), 0.3, PDF_BORDER),
        ("TOPPADDING",    (0, 0), (-1, 0),  5),
        ("BOTTOMPADDING", (0, 0), (-1, 0),  5),
        ("TOPPADDING",    (0, 1), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("LINEAFTER",     (0, 0), (0, -1),  0.5, PDF_BORDER),
    ]

    tbl = Table(table_data, colWidths=col_widths, repeatRows=1,
                hAlign="LEFT", splitByRow=True)
    tbl.setStyle(TableStyle(style_cmds))
    story.append(tbl)
    story.append(Spacer(1, 6 * mm))
    story.append(HRFlowable(width="100%", thickness=0.5,
                             color=colors.HexColor("#c0cdd8"), spaceAfter=4))
    story.append(Paragraph(
        f"Emerald IT Managed Solutions · Confidential · {len(rows)} endpoints · "
        f"Data sourced from Sophos Central",
        ParagraphStyle("Footer", fontName="Helvetica", fontSize=6.5,
                       textColor=PDF_MUTED, alignment=TA_CENTER),
    ))

    doc.build(story, onFirstPage=_pdf_bg, onLaterPages=_pdf_bg)
    return buf.getvalue()


def _pdf_bg(canvas, doc):
    canvas.saveState()
    W, H = doc.pagesize
    canvas.setFillColor(colors.white)
    canvas.rect(0, 0, W, H, fill=1, stroke=0)
    canvas.setFillColor(PDF_ACCENT)
    canvas.rect(0, H - 3, W, 3, fill=1, stroke=0)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(PDF_MUTED)
    canvas.drawRightString(W - 18 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


# ── HTTP server ───────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, (BrokenPipeError, ConnectionResetError)):
            return
        super().handle_error(request, client_address)

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")

    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path
        qs     = parse_qs(parsed.query)

        if path in ("/", "/index.html"):
            self._file("index.html", "text/html")

        elif path == "/api/columns":
            self._json(200, {
                "columns":  [{"key": k, "label": l, "group": g} for k, l, g in ALL_COLUMNS],
                "defaults": DEFAULT_COLUMNS,
            })

        elif path == "/api/customers":
            try:
                tenants = get_tenants_list()
                self._json(200, {"customers": [t["name"] for t in tenants]})
            except Exception as e:
                log(f"Customer fetch error: {e}\n{traceback.format_exc()}")
                self._json(500, {"error": str(e)})

        elif path == "/api/sync-customers":
            try:
                items = get_tenants_list(force=True)
                self._json(200, {"customers": [t["name"] for t in items]})
            except Exception as e:
                log(f"Sync error: {e}\n{traceback.format_exc()}")
                self._json(500, {"error": str(e)})

        elif path == "/api/export":
            customer = qs.get("customer", [None])[0]
            fmt      = qs.get("format", ["csv"])[0].lower()
            cols_raw = qs.get("columns", [",".join(DEFAULT_COLUMNS)])[0]
            selected = [c.strip() for c in cols_raw.split(",") if c.strip() in COLUMN_KEYS]
            if not selected:
                selected = DEFAULT_COLUMNS
            if not customer:
                self._json(400, {"error": "Missing customer parameter"})
                return
            try:
                log(f"Generating {fmt.upper()} for: {customer} ({len(selected)} cols)")
                rows      = fetch_customer_rows(customer)
                safe_name = customer.replace(" ", "_").replace("/", "-")
                ts        = datetime.now().strftime("%Y%m%d_%H%M")
                self._deliver(fmt, rows, selected, safe_name, ts, customer)
            except Exception as e:
                log(f"Export error: {e}\n{traceback.format_exc()}")
                self._json(500, {"error": str(e)})

        elif path == "/api/export-all":
            fmt      = qs.get("format", ["csv"])[0].lower()
            cols_raw = qs.get("columns", [",".join(DEFAULT_COLUMNS)])[0]
            selected = [c.strip() for c in cols_raw.split(",") if c.strip() in COLUMN_KEYS]
            if not selected:
                selected = DEFAULT_COLUMNS
            try:
                log(f"Generating {fmt.upper()} for ALL customers ({len(selected)} cols)")
                rows = fetch_all_customer_rows()
                ts   = datetime.now().strftime("%Y%m%d_%H%M")
                self._deliver(fmt, rows, selected, "all_customers", ts, "All Customers")
            except Exception as e:
                log(f"Export-all error: {e}\n{traceback.format_exc()}")
                self._json(500, {"error": str(e)})

        else:
            self.send_response(404)
            self.end_headers()

    def _deliver(self, fmt, rows, selected, safe_name, ts, display_name):
        if fmt == "pdf":
            data     = generate_pdf(rows, selected, display_name)
            filename = f"{safe_name}_sophos_{ts}.pdf"
            ctype    = "application/pdf"
        else:
            data     = generate_csv(rows, selected)
            filename = f"{safe_name}_sophos_{ts}.csv"
            ctype    = "text/csv; charset=utf-8"

        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self._cors()
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass
        log(f"{fmt.upper()} delivered: {display_name} ({len(data)} bytes)")

    def _file(self, filename, content_type):
        try:
            with open(filename, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self._cors()
            self.end_headers()
            try:
                self.wfile.write(content)
            except (BrokenPipeError, ConnectionResetError):
                pass
        except FileNotFoundError:
            self.send_response(404)
            self.end_headers()

    def _json(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self._cors()
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


if __name__ == "__main__":
    log("Sophos Central Device Export Tool starting on port 8080...")
    if not SOPHOS_CLIENT_ID or not SOPHOS_CLIENT_SECRET:
        log("!! WARNING: SOPHOS_CLIENT_ID / SOPHOS_CLIENT_SECRET not set. API calls will fail.")
    if not REPORTLAB_OK:
        log("!! WARNING: ReportLab not installed — PDF export disabled.")
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
