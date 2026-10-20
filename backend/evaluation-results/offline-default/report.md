# RepoSentinel synthetic security evaluation

Dataset version: `1.0.0`  
Mode: `offline-default`

Small synthetic results do not establish production security effectiveness.

## Metric definitions

The unit of analysis is one fixture/category pair, not one finding. TP: positive label and detected; FP: negative label and detected; FN: positive label and not detected; TN: negative label and not detected. Precision denominator = TP+FP; recall denominator = TP+FN; F1 is the harmonic mean of precision and recall; false-positive-rate denominator = FP+TN. Undefined metric denominators are `null`. `cases` counts included observations; `excluded_cases` counts inconclusive labels or categories without a successful supporting scanner. The JSON `metric_observations` list records ground truth, prediction, inclusion, and exclusion reason for independent recalculation.

## Scanner availability

| Scanner | Status | Reason |
|---|---|---|
| gitleaks | not_requested | Use --local-tools to run installed local scanner executables. |
| heuristic | completed | Built-in scanner; always run. |
| osv | skipped | The existing OSV integration has no guaranteed offline database mode; network access is not used by this evaluation. |
| semgrep | not_requested | Use --local-tools to run installed local scanner executables. |

## Unit-level rule metrics

| Category | Rule IDs | N included | Excluded | TP | FP | FN | TN | Precision | Recall | F1 | FPR |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| credential | HEURISTIC-HARDCODED-CREDENTIAL | 9 | 4 | 1 | 0 | 0 | 8 | 1.0 | 1.0 | 1.0 | 0.0 |
| debug | HEURISTIC-DEBUG-ENABLED | 9 | 4 | 1 | 0 | 0 | 8 | 1.0 | 1.0 | 1.0 | 0.0 |
| sql_concat | HEURISTIC-SQL-STRING-CONCAT | 9 | 4 | 1 | 0 | 0 | 8 | 1.0 | 1.0 | 1.0 | 0.0 |
| tls | HEURISTIC-TLS-VERIFY-DISABLED | 9 | 4 | 1 | 0 | 0 | 8 | 1.0 | 1.0 | 1.0 | 0.0 |

## Full-pipeline metrics by category

| Category | N included | Excluded | TP | FP | FN | TN | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| credential | 9 | 0 | 1 | 0 | 0 | 8 | 1.0 | 1.0 | 1.0 | 0.0 |
| debug | 9 | 0 | 1 | 0 | 0 | 8 | 1.0 | 1.0 | 1.0 | 0.0 |
| sql_concat | 9 | 0 | 1 | 0 | 0 | 8 | 1.0 | 1.0 | 1.0 | 0.0 |
| tls | 9 | 0 | 1 | 0 | 0 | 8 | 1.0 | 1.0 | 1.0 | 0.0 |

## Categories not evaluated

| Category | Supporting scanner status | Reason |
|---|---|---|
| dependency | osv: skipped | No successful scanner supports this category. |
| dynamic_code | semgrep: not_requested | No successful scanner supports this category. |

## Overall full-pipeline metrics

```json
{"cases": 36, "denominators": {"f1_precision": 4, "f1_recall": 4, "false_positive_rate": 32, "precision": 4, "recall": 4}, "excluded_cases": 4, "f1": 1.0, "false_negatives": 0, "false_positive_rate": 0.0, "false_positives": 0, "precision": 1.0, "recall": 1.0, "true_negatives": 32, "true_positives": 4}
```

## Vulnerable versus fixed

| Category | Vulnerable target detected | Fixed target absent | Result |
|---|---:|---:|---|
| credential | True | True | passed |
| debug | True | True | passed |
| tls | True | True | passed |
| sql_concat | True | True | passed |
| dynamic_code | n/a | n/a | Not evaluated: Required scanner semgrep was not run. |

## Cases

| Fixture | Ground truth | Category | Expected rule IDs | Detected rule IDs | Unexpected categories | Limitations |
|---|---|---|---|---|---|---|
| credential-vulnerable | vulnerable | credential | HEURISTIC-HARDCODED-CREDENTIAL | HEURISTIC-HARDCODED-CREDENTIAL | none | Fake value only; the pattern does not establish a genuine credential. |
| credential-fixed | fixed | credential | none | none | none | The value is read from runtime environment configuration. |
| debug-vulnerable | vulnerable | debug | HEURISTIC-DEBUG-ENABLED | HEURISTIC-DEBUG-ENABLED | none | none |
| debug-fixed | fixed | debug | none | none | none | Production configuration is represented by a false literal. |
| tls-vulnerable | vulnerable | tls | HEURISTIC-TLS-VERIFY-DISABLED | HEURISTIC-TLS-VERIFY-DISABLED | none | none |
| tls-fixed | fixed | tls | none | none | none | Uses the HTTP client's default verification behavior. |
| sql-vulnerable | vulnerable | sql_concat | HEURISTIC-SQL-STRING-CONCAT | HEURISTIC-SQL-STRING-CONCAT | none | A text pattern alone does not establish injection or reachability. |
| sql-fixed | fixed | sql_concat | none | none | none | Parameterized query behavior is represented syntactically only. |
| dynamic-vulnerable | vulnerable | dynamic_code | reposentinel-dangerous-eval | none | none | Covered by the local Semgrep rule only when local-tools mode is requested and Semgrep is installed. |
| dynamic-fixed | fixed | dynamic_code | none | none | none | AST parsing is safer than evaluation but still requires application-specific validation. |
| dependency-unverified-declaration | inconclusive | dependency | none | none | none | OSV-Scanner is not invoked by the offline runner because the current integration does not guarantee an offline vulnerability database. This version declaration is not labeled vulnerable without advisory evidence. |
| dependency-removed | inconclusive | dependency | none | none | none | No advisory or fixed version is asserted; this case is not scored offline. |
| benign-patterns | negative | benign | none | none | none | One small negative sample cannot estimate real-world false-positive rates. |

## Limitations and errors

- A small synthetic dataset does not establish production security effectiveness.
- Code fixtures are scanned as text and never executed.
- OSV dependency findings are not scored because the current integration does not guarantee offline operation.
- Precision, recall, F1, and false-positive rate describe this fixture set only; undefined denominators are null.
