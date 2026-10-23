# Method comparison

Generated 2026-10-23 10:21 by `scripts/compare_methods.py`.
Labeled set: 116 events (42 malicious, 74 benign). LLM: `qwen2.5:3b`, temperature 0, seed 42.

| Method | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| Rules only | 31 | 1 | 11 | 73 | 0.97 | 0.74 | 0.84 |
| LLM only - run 1 | 7 | 9 | 35 | 65 | 0.44 | 0.17 | 0.24 |
| Hybrid (rules OR LLM) - run 1 | 31 | 10 | 11 | 64 | 0.76 | 0.74 | 0.75 |
| LLM only - run 2 (label removed) | 7 | 10 | 35 | 64 | 0.41 | 0.17 | 0.24 |
| Hybrid (rules OR LLM) - run 2 (label removed) | 31 | 10 | 11 | 64 | 0.76 | 0.74 | 0.75 |
| ML anomaly (top 5%) | 2 | 7 | 40 | 67 | 0.22 | 0.05 | 0.08 |

## Recall per technique

| Technique | Events | Rules only | LLM only - run 1 | Hybrid (rules OR LLM) - run 1 | LLM only - run 2 (label removed) | Hybrid (rules OR LLM) - run 2 (label removed) | ML anomaly (top 5%) |
|---|---|---|---|---|---|---|---|
| Discovery (T1033/T1087/T1082) | 14 | 4/14 | 0/14 | 4/14 | 0/14 | 4/14 | 0/14 |
| T1003 (sim) | 2 | 2/2 | 0/2 | 2/2 | 0/2 | 2/2 | 0/2 |
| T1021.001 (sim) | 1 | 1/1 | 0/1 | 1/1 | 0/1 | 1/1 | 0/1 |
| T1053.005 | 1 | 1/1 | 0/1 | 1/1 | 0/1 | 1/1 | 0/1 |
| T1059.001 | 1 | 1/1 | 0/1 | 1/1 | 0/1 | 1/1 | 0/1 |
| T1059.001 (sim) | 1 | 1/1 | 0/1 | 1/1 | 0/1 | 1/1 | 0/1 |
| T1070.001 (sim) | 2 | 2/2 | 0/2 | 2/2 | 0/2 | 2/2 | 1/2 |
| T1098 | 2 | 1/2 | 0/2 | 1/2 | 0/2 | 1/2 | 0/2 |
| T1105 (sim) | 2 | 2/2 | 0/2 | 2/2 | 0/2 | 2/2 | 0/2 |
| T1110 | 7 | 7/7 | 7/7 | 7/7 | 7/7 | 7/7 | 0/7 |
| T1136.001 | 2 | 2/2 | 0/2 | 2/2 | 0/2 | 2/2 | 0/2 |
| T1490 (sim) | 2 | 2/2 | 0/2 | 2/2 | 0/2 | 2/2 | 1/2 |
| T1543.003 (sim) | 2 | 2/2 | 0/2 | 2/2 | 0/2 | 2/2 | 0/2 |
| T1547.001 (sim) | 1 | 1/1 | 0/1 | 1/1 | 0/1 | 1/1 | 0/1 |
| T1562.001 (sim) | 2 | 2/2 | 0/2 | 2/2 | 0/2 | 2/2 | 0/2 |

## Run 1 vs run 2

- Run 1: event text as stored. Simulated events had `(simulated)` in `message` and `SIM-WS01\` in `user`; real events had the full multi-line Windows message (which names the real host).
- Run 2 (label removed): same model, prompt, temperature 0 and seed; only the event text changed, the same way for real and simulated events: `message` cut to its first line with `(simulated)` removed, both host names replaced by `HOST` in `command_line`/`message`, and `user` reduced to the bare account name. Real events therefore lose the detail lines of their message (e.g. target account of a 4625/4720).
- Rules and ML do not use the LLM and are identical in both runs.

## LLM cost

- Run 1: average 8.23 s/event over 116 events; invalid / unparseable replies: 0 (counted as positive).
- Run 2 (label removed): average 4.87 s/event over 116 events; invalid / unparseable replies: 0 (counted as positive).
- Local CPU/GPU; cached in `docs/llm_cache.json` (run 1) and `docs/llm_cache_run2.json` (run 2).

## Label assumptions

- Real malicious = events on the real host inside a `ground_truth.json` attack window (HH:MM local, end minute inclusive) that also match the technique pattern: 4625 (T1110), 4720 (T1136.001), 4698 (T1053.005), 4732 (T1098), 4688 with `-enc`/`-EncodedCommand`/`-e` (T1059.001), 4688 of whoami/net/net1/ipconfig/systeminfo (discovery; T1033/T1087/T1082 counted as one technique).
- Agent/upload copies of the same record are de-duplicated on (channel, record_id).
- Simulated malicious = one event per `ground_truth.json` simulated entry (event id + `contains`); simulated benign = all other SIM-WS01 events.
- Real benign = 60 random real events (seed 42) outside every attack window, assumed benign without manual review.

## Limitations

- Small n: per-technique recall is often over 1-5 events; one event changes the numbers a lot.
- Labels were made by us, from our own attack log and patterns; no independent ground truth.
- The rules were written for exactly these attacks and simulations, so rule recall is optimistic and the comparison favours rules (and hybrid).
- Rules see the whole event stream (e.g. brute-force clustering needs 5 failures); the LLM sees one event at a time with no context, so it cannot spot frequency-based attacks the same way.
- ML only scores 4688 process-creation events and is trained on this host's real events, including the attack window; every non-4688 event counts as an ML negative. Top 5% is a fixed cut, not tuned.
- One small local model (3B), one prompt, one seed; results do not generalise to other LLMs.
