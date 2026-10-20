# Synthetic evaluation

Run from `backend` with the project's Python environment:

```powershell
.\.venv\Scripts\python.exe -m app.core.evaluation
```

The default mode is offline. It reads `tests/evaluation/manifest.json`, scans bundled source text with the built-in heuristic scanner, and writes to `evaluation-results/offline-default/`. Fixture code is never imported, executed, installed, or uploaded.

To additionally try Gitleaks and Semgrep executables already on `PATH`, use:

```powershell
.\.venv\Scripts\python.exe -m app.core.evaluation --local-tools
```

This mode writes to `evaluation-results/local-tools/` and never downloads tools. Scanner status distinguishes installed from successfully completed or failed. A failed scanner's categories are excluded from metric calculation. OSV-Scanner is recorded as skipped because the current integration does not promise an offline advisory database. The OSV adapter is covered separately by a synthetic subprocess-response test so the default suite needs no network.

The report compares category-level fixture labels with exact, declared rule-ID mappings. A metric observation is one fixture/category pair; JSON includes the ground truth, prediction, inclusion flag, and exclusion reason so counts can be reproduced. Inconclusive ground truth and categories without a successfully completed supporting scanner are excluded rather than treated as true negatives. `null` metrics mean that the denominator is zero. Pair checks target only the paired category; unrelated findings are reported separately. A small synthetic dataset does not establish production security effectiveness.
