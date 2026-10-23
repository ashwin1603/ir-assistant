# Sample Sigma rules

Hand-written for this project to demo **Settings → Detection → Import Sigma rule**.
They are original examples in Sigma format (new UUIDs), not copies of SigmaHQ rules.
Imported rules are saved to `backend/rules/imported/` and start **disabled**; enable them with the toggle.

| File | Fields / modifiers used | ATT&CK |
|---|---|---|
| certutil_download.yml | Image endswith, CommandLine contains+all | T1105 |
| office_spawns_shell.yml | ParentImage endswith, Image endswith | T1204.002, T1059 |
| service_in_temp.yml | ServiceFileName contains, EventID | T1543.003 |
| shadow_copy_delete.yml | CommandLine re, `and not` filter | T1490 |
