NOTES AND CUSTOMIZATION for risk_sync.py

** SEE COMMENTS IN risk_sync.py FOR INSTALL NOTES **

Where to store the risk register: This writes to risk_register.csv. Swap upsert_csv() with a function that hits your internal risk-register DB or GRC tool API if you have one.

What counts as a vulnerability or audit finding?

Refine JIRA_JQL to match your labels, issue types, or custom fields.

Refine SN_QUERY and infer_category_snow() to match your ServiceNow schema.

Risk scoring: Simple likelihood × impact (1–5). Tweak SEVERITY_MAP or compute likelihood differently.

Watermarks: The script stores last synced timestamps in .risk_sync_state.json , so re-runs are incremental.

Security: Use a secrets manager or .env file permissions; never hard-code tokens.

LEARNING RESOURCES

GRC Playground

https://github.com/ashpearce/GRC-Playground

GRC Engineer Podcast

https://open.spotify.com/show/3SkXwuXewy0qXXhICy5e6W?

GRC Engineering Manifest
o
https://grc.engineering/

GRC Engineering Learning Hub

https://grc.engineering/learning-hub/

CONTACT DARRYL

darrylm@gmail.com

https://www.linkedin.com/in/darrylmacleod/
