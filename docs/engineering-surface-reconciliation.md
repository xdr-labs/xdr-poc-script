# CLI Surface Reconciliation Contract

Primary surface: CLI/TUI

Before a user-facing release is accepted, execute the exact candidate through the real operator entry point and reconcile commands/prompts/output against the committed README/operator guidance.

Required PASS evidence:
- the documented entry point starts on a supported environment or safe fixture;
- the primary operator flow is discoverable without undocumented commands;
- cancellation/help/dry-run behavior matches the documented safety model;
- no credential or secret value is echoed into evidence;
- candidate HEAD and observed command/output are recorded.

Static parsing or unit tests alone are not user-surface execution PASS.
