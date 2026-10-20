# RepoSentinel synthetic security evaluation

Dataset version: `1.0.0`  
Mode: `offline-default`

Small synthetic results do not establish production security effectiveness.

## Metric definitions

Counts use fixture-category labels and category-level scanner detections. TP: labeled positive and detected; FP: labeled negative and detected; FN: labeled positive and not detected; TN: labeled negative and not detected. Precision = TP/(TP+FP), recall = TP/(TP+FN), F1 = harmonic mean, FPR = FP/(FP+TN). Undefined denominators are `null`.

## Scanner availability

| Scanner | Status | Reason |
|---|---|---|
| gitleaks | not_requested | Use --local-tools to run installed local scanner executables. |
| heuristic | available | Built-in scanner; always run. |
| osv | skipped | The existing OSV integration has no guaranteed offline database mode; network access is not used by this evaluation. |
| semgrep | not_requested | Use --local-tools to run installed local scanner executables. |

## Unit-level rule metrics

| Category | Rule IDs | TP | FP | FN | TN | Precision | Recall | F1 | FPR |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| credential | HEURISTIC-HARDCODED-CREDENTIAL | 1 | 0 | 0 | 8 | 1.0 | 1.0 | 1.0 | 0.0 |
| debug | HEURISTIC-DEBUG-ENABLED | 1 | 0 | 0 | 8 | 1.0 | 1.0 | 1.0 | 0.0 |
| sql_concat | HEURISTIC-SQL-STRING-CONCAT | 1 | 0 | 0 | 8 | 1.0 | 1.0 | 1.0 | 0.0 |
| tls | HEURISTIC-TLS-VERIFY-DISABLED | 1 | 0 | 0 | 8 | 1.0 | 1.0 | 1.0 | 0.0 |

## Full-pipeline metrics by category

| Category | TP | FP | FN | TN | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| credential | 1 | 0 | 0 | 8 | 1.0 | 1.0 | 1.0 | 0.0 |
| debug | 1 | 0 | 0 | 8 | 1.0 | 1.0 | 1.0 | 0.0 |
| sql_concat | 1 | 0 | 0 | 8 | 1.0 | 1.0 | 1.0 | 0.0 |
| tls | 1 | 0 | 0 | 8 | 1.0 | 1.0 | 1.0 | 0.0 |

## Overall full-pipeline metrics

```json
{"cases": 36, "f1": 1.0, "false_negatives": 0, "false_positive_rate": 0.0, "false_positives": 0, "precision": 1.0, "recall": 1.0, "true_negatives": 32, "true_positives": 4}
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
