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

## Engineering System User Acceptance v2 — mandatory execution semantics

- **ChatGPT itself is the executor and final auditor.** ChatGPT directly acts as the applicable real User/Operator/Admin persona and drives the actual supported public surface. Coding agents, alternate models, wrappers, scripted replays, CI jobs, unit/component/API suites, and static scanners are supporting evidence only and cannot produce Surface Reconciliation PASS.
- Start **capability-first and black-box-first**. The acting persona discovers the product from public help/navigation/controls/output before source/parser/route/test inspection. Implementation knowledge is auditor-only after the corresponding public evidence is frozen.
- Reconcile every applicable capability through public discovery, role/context, terminology, lifecycle, state/empty/error semantics, next action, recovery guidance, risky/destructive-action safety, and user-visible result. Every mandatory capability/public control receives an explicit disposition; FAIL/PARTIAL/BLOCKED/not-run never becomes PASS.
- **A finding is not a stop condition.** Preserve evidence and continue every safe independent scenario. Do not patch product/source/contract during the frozen discovery pass. After safe coverage is exhausted, freeze the complete finding set, remediate it as one bounded batch, and rerun Surface Reconciliation from the beginning on the new candidate.
- For CLI products, ChatGPT directly uses the actual supported public CLI/TUI; parser/unit tests, direct internal APIs, and scripted replay cannot substitute.
- Retain exact candidate HEAD, committed contract identity/digest, machine-readable capability/surface/findings ledgers, and a ledger-derived summary. Release PASS requires 100% applicable capability/public-surface coverage, zero mandatory FAIL/PARTIAL/BLOCKED, and zero unresolved blocking finding.
- If the product supports an AI-assisted public user path, run the same applicable user goal through that path using only user-visible information and require semantically equivalent supported guidance/outcome.
