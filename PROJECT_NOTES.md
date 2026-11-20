# Implementation notes

- All AWS operations in the scanner are read-only inventory/configuration APIs.
- There are no automatic remediation buttons or write APIs.
- Scans are explicitly scoped to the account resolved from the active AWS credential profile and the regions entered by the operator.
- Access-denied or service errors are surfaced in the diagnostics list so a partial scan is not silently presented as complete.
- Unit tests validate deterministic local detection rules without AWS connectivity.
