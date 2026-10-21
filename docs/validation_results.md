# Detection validation results

Generated 2026-10-21 17:52 by `scripts/validate.py` from `docs/ground_truth.json`.

## Real attacks - DESKTOP-M35SOM0 (2026-10-21, 10:30-11:20 local)

| Technique | Expected | Detected | Missed |
|---|---|---|---|
| T1033 | 1 | 1 | 0 |
| T1053.005 | 1 | 1 | 0 |
| T1059.001 | 1 | 1 | 0 |
| T1082 | 1 | 1 | 0 |
| T1087 | 1 | 1 | 0 |
| T1098 | 1 | 1 | 0 |
| T1110 | 1 | 1 | 0 |
| T1136.001 | 2 | 2 | 0 |

- **Recall:** 100% (9/9) expected technique instances detected
- **Precision:** 88% (7/8) detections in the window match ground truth
- **False positives:** 1
  - Suspicious PowerShell script block x10 (developer tooling)

## Simulated events - SIM-WS01

| Technique | Expected | Detected | Missed |
|---|---|---|---|
| T1003 | 2 | 2 | 0 |
| T1021.001 | 1 | 1 | 0 |
| T1059.001 | 1 | 1 | 0 |
| T1070.001 | 2 | 2 | 0 |
| T1105 | 2 | 2 | 0 |
| T1490 | 2 | 2 | 0 |
| T1543.003 | 2 | 2 | 0 |
| T1547.001 | 1 | 1 | 0 |
| T1562.001 | 2 | 2 | 0 |

- **Recall:** 100% (15/15) malicious events caught by the expected rule
- **Precision:** 100% (15/15)
- **Benign events:** 14 (expected 14), false positives: 0
