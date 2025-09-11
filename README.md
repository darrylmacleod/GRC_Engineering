Notes & customization

Where to store the risk register: This writes to risk_register.csv. Swap upsert_csv() with a function that hits your internal risk-register DB or GRC tool API if you have one.

What counts as a vulnerability or audit finding?

Refine JIRA_JQL to your labels, issuetypes, or custom fields.

Refine SN_QUERY and infer_category_snow() to match your ServiceNow schema.

Risk scoring: Simple likelihood × impact (1–5). Tweak SEVERITY_MAP or compute likelihood differently.

Watermarks: The script stores last synced timestamps in .risk_sync_state.json so re-runs are incremental.

Security: Use a secrets manager or .env file permissions; never hard-code tokens.
