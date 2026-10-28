# Presentation outline (8 slides)

Use this as a slide-ready outline. Capture screenshots on the presentation machine after local credentials have been rotated. Show synthetic labels and hide usernames, hostnames, tokens, `.env`, and real log content.

1. **Title and team** — AI-Powered Incident Response Assistant for Security Log Analysis; course and team members.
2. **Problem** — analysts manually inspect large volumes of logs; investigations need evidence, context, prioritization, and consistent reporting.
3. **Goals and scope** — upload/collect logs; detect suspicious activity; ATT&CK map; timeline and risk; recommendations and report. State that processing is on demand and actions are simulated.
4. **Architecture** — show the diagram from `architecture.md`: collector/upload → normalization → SQLite → detection/correlation → evidence/AI → analyst interface.
5. **Detection and evaluation** — show rule-based detection and ATT&CK mapping; summarize the dated validation and method comparison from `validation_results.md` and `method_comparison.md`, including small sample size and weak supplementary ML results.
6. **Investigation demo** — use a screenshot of a clearly simulated incident with timeline, matched event IDs, ATT&CK techniques, risk score, and graph.
7. **Analyst workflow and security** — show recommendations awaiting approval, viewer redaction/roles, MFA, audit verification, logout revocation, and upload/export protections. State that response actions never execute.
8. **Limitations and next steps** — local demo, no full production streaming, small evaluation sample, local AI option, clean-machine validation and credential rotation remaining; conclude with learning outcomes.

## Screenshot capture checklist

- Dashboard with simulated/demo mode visible.
- Detection list filtered to a simulated host.
- Incident detail with evidence and timeline.
- ATT&CK technique detail.
- Recommendations showing pending state and simulated-only action wording.
- Audit page with a successful integrity check.

Do not fabricate results or use a screenshot containing actual credentials or personal/organizational telemetry.
