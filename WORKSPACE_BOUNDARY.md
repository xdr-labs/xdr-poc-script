# Workspace Safety / Repository Boundary

**문서 버전:** 1.0.0  
**적용 범위:** `xdr-poc-script` repository (standalone DSP / PoC)

---

## 1. Context

DSP development happens in a **standalone repository**, not inside
`xdr-lab-appliance`.

| Repository | Role | Writable DSP? |
|------------|------|---------------|
| **xdr-poc-script** (`/home/aella/xdr-poc-script`) | DSP / PoC scenarios, tests, releases | **Yes** |
| **xdr-lab-appliance** | KVM lab, `aella_cli`, bootstrap, installer | **No** |

The lab appliance may **consume** DSP as an external dependency (clone, env var,
optional wrapper scripts). It must not vendor editable DSP source.

---

## 2. Canonical Source Rule

| Location | Status |
|----------|--------|
| `git@github.com:RickLee-kr/xdr-poc-script.git` | **Official SoT** |
| Branch `release/v1.4.0-rc` | Active operator release line (menu/install default) |
| Tag `v1.4.0` | Historical freeze only — do not use for install/update |
| Local path `/home/aella/xdr-poc-script` | Default operator checkout |
| `detection-scenario-platform.git` | **Deprecated** — do not push |
| `xdr-lab-appliance/detection-scenario-platform/` | **Removed** — never re-add |

---

## 3. Absolute Rules

### 3.1 DSP work (this repo only)

All DSP code, tests, scenarios, and DSP documentation updates belong **only**
under this repository root:

```
/home/aella/xdr-poc-script/
├── dsp/
├── scenarios/
├── tests/
├── docs/
└── pyproject.toml
```

### 3.2 Do not edit in xdr-lab-appliance

- Do not commit DSP changes under `xdr-lab-appliance/`.
- Do not recreate `detection-scenario-platform/` inside the appliance tree.
- Legacy bash PoC in appliance `legacy/bash-poc/` is **read-only archive**.

---

## 4. Pre-Commit Checklist

Before every commit:

1. **`pwd`** — must be `/home/aella/xdr-poc-script` (or your clone of it).
2. **`git remote -v`** — `origin` must be `RickLee-kr/xdr-poc-script.git`.
3. **Scope** — changes are DSP/PoC only; no appliance/bootstrap edits mixed in.

---

## 5. Lab integration (external)

Future or optional integration with the lab:

```
aella_cli lab deploy …          ← xdr-lab-appliance
        │
        ▼ (operator runs separately)
xdr-poc-script: dsp run …       ← external checkout
```

Appliance documents the clone path in `docs/DSP_EXTERNAL_DEPENDENCY.md`.

---

## 6. Related Documents

- [docs/REPOSITORY_GOVERNANCE.md](./docs/REPOSITORY_GOVERNANCE.md)
- Appliance: `docs/REPOSITORY_BOUNDARY.md`, `docs/DSP_EXTERNAL_DEPENDENCY.md`
