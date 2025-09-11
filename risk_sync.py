#!/usr/bin/env python3
import csv
import json
import os
from datetime import datetime, timedelta, timezone
from dateutil.parser import isoparse

import requests

STATE_FILE = ".risk_sync_state.json"
RISK_REGISTER_CSV = "risk_register.csv"

# ---------------------------
# Utilities
# ---------------------------
def now_utc_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def load_state():
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE, "r") as f:
        return json.load(f)

def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

def default_since():
    # First run watermark (7 days back)
    return (datetime.now(timezone.utc) - timedelta(days=7)).replace(microsecond=0).isoformat()

def get_since(state_key: str):
    # Optional override via env
    override = os.getenv("START_SINCE_ISO", "").strip()
    if override:
        try:
            _ = isoparse(override)
            return override
        except Exception as e:
            print(f"[Error] Invalid START_SINCE_ISO value: '{override}'. Error: {e}")
    if not is_valid_iso(new_watermark_iso):
        print(f"[Error] Invalid new watermark ISO: '{new_watermark_iso}'")
        return
    state = load_state()
    return state.get(state_key, default_since())

def update_since(state_key: str, new_watermark_iso: str):
    def is_valid_iso(date_str):
        try:
            isoparse(date_str)
            return True
        except Exception:
            return False
    state = load_state()
    # keep the MAX watermark to avoid going backwards
    prev = state.get(state_key)
    try:
        if not prev or (is_valid_iso(new_watermark_iso) and is_valid_iso(prev) and isoparse(new_watermark_iso) > isoparse(prev)):
            state[state_key] = new_watermark_iso
            save_state(state)
    except Exception:
        # if state corrupted, just set it
        state[state_key] = new_watermark_iso
        save_state(state)

def ensure_csv_headers(path, headers):
    exists = os.path.exists(path)
    if not exists:
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=headers)
    if not exists:
        first = None
    else:
        # if file exists but missing headers, rewrite (rare)
        with open(path, "r", newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
        if first is None or first != headers:
    if first is None or first != headers:
        if first != headers:
            rows = []
            with open(path, "r", newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
                for r in rows:
                    writer.writerow({h: r.get(h, "") for h in headers})

def load_existing_by_id(path, key_field):
    if not os.path.exists(path):
        return {}
    with open(path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return {row[key_field]: row for row in reader}

def upsert_csv(path, key_field, rows, headers):
    ensure_csv_headers(path, headers)
    existing = load_existing_by_id(path, key_field)
    # Apply upserts
    for r in rows:
        existing[r[key_field]] = r
    # Write back
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for _, row in existing.items():
            writer.writerow(row)

# ---------------------------
# Normalization & scoring
# ---------------------------
RISK_HEADERS = [
    "risk_id", "source", "title", "description", "status",
    "owner", "severity", "likelihood", "impact", "risk_score",
    "category", "tags", "detected_at", "last_seen", "url"
]

SEVERITY_MAP = {
    "critical": 5,
    "blocker": 5,
    "high": 4,
    "major": 4,
    "medium": 3,
    "moderate": 3,
    "low": 2,
    "minor": 2,
    "info": 1,
    "informational": 1,
    "trivial": 1
}

def score_from_severity(sev_text: str) -> int:
    if not sev_text:
        return 3
    s = sev_text.lower()
    # numeric? try to parse
    try:
        n = int(s)
        return max(1, min(5, n))
    except ValueError:
        return SEVERITY_MAP.get(s, 3)

def normalize_common(
    risk_id, source, title, description, status, owner, severity_text,
    category, tags, detected_at_iso, last_seen_iso, url,
    likelihood=3
):
    impact = score_from_severity(severity_text)
    # Simple risk score = likelihood * impact (1–25)
    risk_score = likelihood * impact
    return {
        "risk_id": risk_id,
        "source": source,
        "title": (title or "")[:250],
        "description": (description or "").strip(),
        "status": status or "Open",
        "owner": owner or "",
        "severity": severity_text or "",
        "likelihood": str(likelihood),
        "impact": str(impact),
        "risk_score": str(risk_score),
        "category": category or "",
        "tags": ",".join(tags) if isinstance(tags, list) else (tags or ""),
        "detected_at": detected_at_iso or "",
        "last_seen": last_seen_iso or now_utc_iso(),
        "url": url or ""
    }

# ---------------------------
# Jira
# ---------------------------

def determine_jira_category(labels, issue_type):
    """
    Determines the category for a Jira issue based on its labels and issue type.
    """
    labels_lower = [x.lower() for x in labels]
    if "vulnerability" in labels_lower or issue_type.lower() in ("vulnerability", "security finding"):
        return "Vulnerability"
    return "Audit Finding"
def fetch_jira(since_iso: str):
    base = os.getenv("JIRA_BASE_URL", "").rstrip("/")
    email = os.getenv("JIRA_EMAIL")
    token = os.getenv("JIRA_API_TOKEN")
    jql = os.getenv("JIRA_JQL", "ORDER BY updated DESC")

    if not (base and email and token):
        return [], since_iso  # Jira not configured

    # We add an updated >= since filter to the JQL (if not present)
    # Jira updated >= "2025-09-01 00:00"
    since_dt = isoparse(since_iso)
    since_jira = since_dt.strftime("%Y-%m-%d %H:%M")

    # Be gentle: if user already filters by updated, we won't force our clause
    if "updated" not in jql.lower():
        if jql.strip().lower().startswith("order by"):
            jql = f'updated >= "{since_jira}" {jql}'
        else:
            jql = f'({jql}) AND updated >= "{since_jira}"'

    url = f"{base}/rest/api/3/search"
    start_at = 0
    max_results = 50
    all_issues = []
    newest_update = since_iso

    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    session = requests.Session()
    retries = Retry(total=5, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retries))

    while True:
        payload = {
            "jql": jql,
            "startAt": start_at,
            "maxResults": max_results,
            "fields": [
                "summary", "description", "status", "assignee",
                "labels", "priority", "updated", "created", "issuetype"
            ]
        }
        r = session.post(url, json=payload, auth=auth, headers=headers, timeout=30)
            ]
        }
        r = requests.post(url, json=payload, auth=auth, headers=headers, timeout=30)
        try:
            r.raise_for_status()
        except requests.HTTPError as e:
            print(f"[Jira] HTTP error: {e}")
            print(f"[Jira] Response content: {r.text}")
            raise
        data = r.json()
        issues = data.get("issues", [])
        all_issues.extend(issues)
        # Track watermark
        for it in issues:
            updated = it.get("fields", {}).get("updated")
            if updated:
                try:
                    up = isoparse(updated)
                    if up > isoparse(newest_update):
                        newest_update = up.isoformat()
                except ValueError:
                    pass
        if start_at + max_results >= data.get("total", 0):
            break
        start_at += max_results

    # Normalize
    normalized = []
    for it in all_issues:
        key = it.get("key")
        f = it.get("fields", {})
        title = f.get("summary")
        desc = safe_jira_description(f.get("description"))
        status = (f.get("status") or {}).get("name", "Open")
        assignee = (f.get("assignee") or {}).get("displayName", "")
        labels = f.get("labels") or []
        priority = (f.get("priority") or {}).get("name", "")
        created = f.get("created")
        updated = f.get("updated") or now_utc_iso()
        issue_type = (f.get("issuetype") or {}).get("name", "")

        url_issue = f"{base}/browse/{key}"

        # Map Jira -> risk
        category = determine_jira_category(labels, issue_type)
        n = normalize_common(
            risk_id=f"JIRA-{key}",
            source="Jira",
            title=title,
            description=desc,
            status=status,
            owner=assignee,
            severity_text=priority or "Medium",
            category=category,
            tags=labels,
            detected_at_iso=created,
            last_seen_iso=updated,
            url=url_issue,
            likelihood=likelihood_from_status(status)
        )
        normalized.append(n)

    return normalized, newest_update

def safe_jira_description(desc):
    """
    Jira Cloud may return rich text; this function extracts a compact string.

    Example of rich text input:
    {
        "type": "doc",
        "content": [
            {
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": "This is a description."}
                ]
            }
        ]
    }
    """
    if isinstance(desc, dict) and "content" in desc:
        return flatten_jira_richtext(desc)
    return desc or ""

def flatten_jira_richtext(doc):
    # Very light flattener: extract text nodes
    out = []
    def walk(n):
        if isinstance(n, dict):
            t = n.get("type")
            if t == "text":
                out.append(n.get("text", ""))
            for c in n.get("content", []) or []:
                walk(c)
        elif isinstance(n, list):
            for c in n:
                walk(c)
    walk(doc)
    return " ".join(out).strip()

def likelihood_from_status(status: str) -> int:
    """
    Determines the likelihood value based on the status of a risk.

    The likelihood is determined as follows:
    - If the status indicates completion (e.g., "done", "closed", "resolved"), the likelihood is low (1).
    - If the status indicates active work (e.g., "in progress", "doing", "investigating"), the likelihood is high (4).
    - For all other statuses, a default medium likelihood (3) is assigned.

    Examples:
    - likelihood_from_status("Resolved") -> 1
    - likelihood_from_status("In Progress") -> 4
    - likelihood_from_status("Open") -> 3

    Args:
        status (str): The status of the risk.

    Returns:
        int: The likelihood value (1 to 5).
    """
    s = (status or "").lower()
    if any(x in s for x in ["done", "closed", "resolved"]):
        return 1
    if any(x in s for x in ["in progress", "doing", "investigating"]):
        return 4
    return 3

# ---------------------------
# ServiceNow
# ---------------------------
def fetch_servicenow(since_iso: str):
    base = os.getenv("SN_BASE_URL", "").rstrip("/")
    user = os.getenv("SN_USER")
    pwd = os.getenv("SN_PASSWORD")
    table = os.getenv("SN_TABLE", "incident")
    query = os.getenv("SN_QUERY", "")

    if not (base and user and pwd):
        return [], since_iso  # ServiceNow not configured

    # Append sys_updated_on >= since to query
    # ServiceNow expects yyyy-mm-dd HH:MM:SS
    since_dt = isoparse(since_iso)
    sn_since = since_dt.strftime("%Y-%m-%d %H:%M:%S")
    if query:
        sn_query = f"{query}^sys_updated_on>={sn_since}"
    else:
        sn_query = f"sys_updated_on>={sn_since}"
    from requests.adapters import HTTPAdapter
    from requests.packages.urllib3.util.retry import Retry

    session = requests.Session()
    retries = Retry(total=5, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retries))

    try:
        r = session.get(url, auth=(user, pwd), headers=headers, params=params, timeout=30)
    except requests.exceptions.RequestException as e:
        print(f"[ServiceNow] Request error: {e}")
        raise
    url = f"{base}/api/now/table/{table}"
    params = {
        "sysparm_query": sn_query,
        "sysparm_limit": "1000"
    }
    headers = {"Accept": "application/json"}
    r = requests.get(url, auth=(user, pwd), headers=headers, params=params, timeout=30)
    r.raise_for_status()
    data = r.json().get("result", [])

    newest_update = since_iso
    normalized = []
    for rec in data:
        key = rec.get("sys_id")
        number = rec.get("number") or key
        title = rec.get("short_description") or f"{table} {number}"
        desc = rec.get("description") or rec.get("u_details") or ""
        status = servicenow_status(rec)
        owner = rec.get("assigned_to", "") if isinstance(rec.get("assigned_to"), str) else (rec.get("assigned_to") or {}).get("display_value", "")
        severity_text = rec.get("severity") or rec.get("priority") or "Medium"
        category = infer_category_snow(rec)
        created = rec.get("sys_created_on")
        updated = rec.get("sys_updated_on")
        url_rec = f"{base}/nav_to.do?uri={table}.do?sys_id={key}"

        if updated:
            try:
                up = isoparse(updated)
                if up > isoparse(newest_update):
                    newest_update = up.isoformat()
            except Exception:
                pass

        n = normalize_common(
            risk_id=f"SN-{number}",
            source="ServiceNow",
            title=title,
            description=desc,
            status=status,
            owner=owner,
            severity_text=severity_text,
            category=category,
            tags=rec.get("u_tags", ""),
            detected_at_iso=created,
            last_seen_iso=updated,
            url=url_rec,
            likelihood=likelihood_from_status(status)
        )
        normalized.append(n)

    return normalized, newest_update

def servicenow_status(rec):
    s = (rec.get("state") or "").lower()
    mapping = {
        "1": "New", "2": "In Progress", "3": "On Hold",
        "6": "Resolved", "7": "Closed", "8": "Canceled"
    }
    # numeric state codes or strings
    if s.isdigit():
        return mapping.get(s, "Open")
    # textual states
    if "progress" in s:
        return "In Progress"
    if "resolve" in s:
        return "Resolved"
    if "close" in s:
    # Check if the text indicates a vulnerability
    if any(x in text for x in ["vulnerability", "cve", "scan"]):
        return "Vulnerability"
    
    # Check if the text indicates an audit finding
    if any(x in text for x in ["audit", "finding", "nonconform"]):
        return "Audit Finding"
def process_jira(all_rows):
    jira_since = get_since("jira_since")
    try:
        jira_rows, jira_new = fetch_jira(jira_since)
        all_rows.extend(jira_rows)
        update_since("jira_since", jira_new)
        print(f"[Jira] Upserts: {len(jira_rows)}; watermark -> {jira_new}")
    except requests.HTTPError as e:
        print(f"[Jira] HTTP error: {e}")
    except Exception as e:
        print(f"[Jira] Error: {e}")

def process_servicenow(all_rows):
    sn_since = get_since("servicenow_since")
    try:
        sn_rows, sn_new = fetch_servicenow(sn_since)
        all_rows.extend(sn_rows)
        update_since("servicenow_since", sn_new)
        print(f"[ServiceNow] Upserts: {len(sn_rows)}; watermark -> {sn_new}")
    except requests.HTTPError as e:
        print(f"[ServiceNow] HTTP error: {e}")
    except Exception as e:
        print(f"[ServiceNow] Error: {e}")

def write_risk_register(all_rows):
    if all_rows:
        with open(RISK_REGISTER_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=RISK_HEADERS)
            writer.writeheader()
            for row in all_rows:
                writer.writerow(row)
        print(f"[Risk Register] Upserted {len(all_rows)} rows -> {RISK_REGISTER_CSV}")
    else:
        print("[Risk Register] No new/updated items.")

def main():
    all_rows = []
    process_jira(all_rows)
    process_servicenow(all_rows)
    write_risk_register(all_rows)
        print(f"[ServiceNow] Upserts: {len(sn_rows)}; watermark -> {sn_new}")
    except requests.HTTPError as e:
        print(f"[ServiceNow] HTTP error: {e}")
    except Exception as e:
        print(f"[ServiceNow] Error: {e}")

    if all_rows:
        with open(RISK_REGISTER_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=RISK_HEADERS)
            writer.writeheader()
            for row in all_rows:
                writer.writerow(row)
        print(f"[Risk Register] Upserted {len(all_rows)} rows -> {RISK_REGISTER_CSV}")
    else:
        print("[Risk Register] No new/updated items.")

if __name__ == "__main__":
    main()
