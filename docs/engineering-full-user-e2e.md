# Full User E2E Contract

Primary operator mission: launch dsp-menu.sh, configure an authorized lab target, run or dry-run a scenario, and inspect the generated report/evidence.

Run this mission on the same exact candidate used for Surface Reconciliation. Use an isolated/authorized lab or deterministic fixture for any action that could affect systems or traffic. Do not turn a destructive or production mutation into an automated test merely to satisfy this contract.

PASS requires:
1. start from the documented user entry point;
2. complete the primary mission without bypassing safety prompts/guards;
3. observe the resulting user-visible status/evidence;
4. verify cancellation/error recovery remains usable;
5. record exact candidate HEAD and PASS/FAIL evidence.
