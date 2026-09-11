# Implementation Audit

| Component | Documented | Implemented | Actually Works | Missing | Action |
| --- | --- | --- | --- | --- | --- |
| Evidence Intake | Yes | Yes | Partially | Validates path, but doesn't handle all missing file edge cases cleanly. Doesn't do MD5 if retained. | Implement strict validation, MD5 hashing, read-only guarantees, and deterministic ID. |
| Disk Analysis | Yes | Yes | Partially | Claims Registry parsing, but actually only extracts metadata (Not full hive parsing). | Explicitly label findings as `METADATA_ONLY` instead of full extraction. Safe timestamps. |
| Offline Memory Analysis | Yes | Yes | Partially | Uses Volatility 3, but fails ungracefully if missing or timeout occurs. | Add robust try-catch, return `NOT_AVAILABLE`/`ERROR`, and handle missing fields. |
| Live RAM Inspection | Yes | Yes | Yes | Uses `ctypes`, skips denied processes. | Ensure no termination/modification, safe error handling on access denied. |
| Network Intelligence | Yes | Yes | Partially | Scans connections, but heuristics are too simplistic (e.g., port 443). | Refine heuristics, explain scoring, do not auto-label C2 based solely on port. |
| Persistence Hunting | Yes | Yes | Partially | Scans registry, but lacks detailed action/executable path mapping. | Include exact source mechanism, distinguish `ACTIVE`/`DORMANT`. |
| DLL Inspection | Yes | Yes | Partially | Flags DLLs, but jumps to "hollowing" conclusion too fast. | Use wording like `POSSIBLE` or `SUSPICIOUS`. Include confidence/risk. |
| Normalization | Yes | No | No | Modules return raw dicts, no unified layer. | Create a normalization layer in `main.py` to map to `CorrelatedEvent`. |
| Timeline Builder | Yes | Yes | Partially | Sorts by timestamp, but needs better missing-timestamp handling. | Keep `UNKNOWN` timestamps, handle timezones, retain source modules. |
| Cross-Module Correlation | Yes | Yes | No | Currently just concatenates or checks string equality. | Implement true evidence graphs with `evidence_a`, `evidence_b`, `confidence`. |
| Threat Scoring | Yes | Yes | Partially | Needs better false-positive control and base rule linking. | Add base rule, severity, MITRE ATT&CK mapping, and confidence levels. |
| Reporting | Yes | Yes | Partially | Generates JSON/HTML, but not the requested Complete Case Object. | Rewrite to use the massive Case Object JSON schema. Keep HTML offline. |
| CLI / Dashboard | Yes | Yes | Partially | Has `--dashboard` and `--scan`, but lacks `--doctor` and `--self-test`. | Implement `--doctor` environment check, `--self-test` mode, and exit codes. |
