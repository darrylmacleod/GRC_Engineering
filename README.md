# GRC_Engineering_101
GRC Engineering 101 - Example

Python script that watches Jira and/or ServiceNow for new/updated vulnerabilities or audit findings and upserts them into a local risk_register.csv (idempotent, incremental, and easy to cron).

It supports:

Jira Cloud (JQL filter)

ServiceNow (Table API query)

Incremental sync via a local .risk_sync_state.json

Simple risk scoring & field mapping

Update-in-place (so edits to existing risks aren’t lost)

1) Install
pip install requests python-dateutil

2) Configure (env vars)

Set the ones you need (you can use both Jira and ServiceNow at the same time):

# --- Jira ---
export JIRA_BASE_URL="https://yourcompany.atlassian.net"
export JIRA_EMAIL="you@company.com"
export JIRA_API_TOKEN="atlassian_api_token"
# e.g., only pull issues tagged as vulnerability or audit
export JIRA_JQL='project = SEC AND (labels in (vulnerability, "audit-finding") OR issuetype in ("Vulnerability","Security Finding")) ORDER BY updated DESC'

# --- ServiceNow ---
export SN_BASE_URL="https://yourinstance.service-now.com"
export SN_USER="api_user"
export SN_PASSWORD="api_password"
# Table can be "incident", "problem", a custom table like "x_sec_finding", etc.
export SN_TABLE="incident"
# Query for vulns/findings updated recently; filter to security category
# (You can refine further for your schema.)
export SN_QUERY='category=security^u_typeINvulnerability,audit_finding'

# --- Behavior ---
# Default is "now - 7d" on first run; after that it uses the saved watermark
# Override to backfill: e.g., "2025-09-01T00:00:00Z"
export START_SINCE_ISO=""

3) Run on a schedule
python risk_sync.py
# or cron (every 15 minutes):
# */15 * * * * /usr/bin/python /path/to/risk_sync.py >> /var/log/risk_sync.log 2>&1
