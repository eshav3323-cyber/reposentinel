"""Offline synthetic evaluation for RepoSentinel's real scanner interfaces.

Fixture source is read as text and passed to scanners; it is never imported,
executed, installed, or sent to a network service.
"""

from __future__ import annotations

import json
import io
import shutil
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.archive_handler import SourceFile, read_repository_zip
from app.core.finding_normalizer import redact_evidence
from app.scanners.heuristic import scan_source_files


class EvaluationError(ValueError):
    """Invalid ground truth or an evaluation process error."""


SCANNER_CATEGORIES = {
    "heuristic": {"credential", "debug", "tls", "sql_concat"},
    "gitleaks": {"credential"},
    "semgrep": {"debug", "tls", "dynamic_code"},
    "osv": {"dependency"},  # skipped: production interface has no guaranteed offline database.
}


def _inside(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise EvaluationError("Ground truth contains an empty fixture path.")
    candidate = (root / relative).resolve()
    if candidate != root.resolve() and root.resolve() not in candidate.parents:
        raise EvaluationError("Ground truth fixture path escapes the fixture directory.")
    return candidate


def load_manifest(manifest_path: Path) -> tuple[dict[str, Any], Path]:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvaluationError("Could not load the evaluation ground-truth manifest.") from exc
    if (not isinstance(manifest, dict) or not isinstance(manifest.get("cases"), list)
            or not manifest["cases"]):
        raise EvaluationError("Ground truth must contain a cases list.")
    cases = manifest["cases"]
    ids: set[str] = set()
    statuses = {"vulnerable", "fixed", "negative", "inconclusive"}
    for case in cases:
        if not isinstance(case, dict):
            raise EvaluationError("Ground truth case must be an object.")
        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id or case_id in ids:
            raise EvaluationError("Ground truth case IDs must be unique nonempty strings.")
        ids.add(case_id)
        if case.get("status") not in statuses:
            raise EvaluationError(f"Ground truth case {case_id} has an invalid status.")
        if (not isinstance(case.get("expected_rule_ids"), list)
                or not all(isinstance(rule_id, str) for rule_id in case["expected_rule_ids"])
                or not isinstance(case.get("expected_categories"), list)
                or not all(isinstance(category, str) for category in case["expected_categories"])
                or not isinstance(case.get("category"), str)
                or not isinstance(case.get("labels"), dict)):
            raise EvaluationError(f"Ground truth case {case_id} has invalid expected labels.")
        fixture = _inside(manifest_path.parent, case.get("path", ""))
        if not fixture.is_dir() or not any(file.is_file() for file in fixture.rglob("*")):
            raise EvaluationError(f"Ground truth fixture {case_id} is missing or empty.")
        for label, expected in case["labels"].items():
            if not isinstance(label, str) or expected not in (True, False, None):
                raise EvaluationError(f"Ground truth case {case_id} has a non-boolean label.")
        positive_labels = {label for label, expected in case["labels"].items() if expected is True}
        if positive_labels != set(case["expected_categories"]):
            raise EvaluationError(f"Ground truth case {case_id} has inconsistent expected categories.")
    mapping = manifest.get("category_rule_ids")
    if (not isinstance(mapping, dict) or not mapping
            or not all(isinstance(category, str) and isinstance(rule_ids, list)
                       and all(isinstance(rule_id, str) for rule_id in rule_ids)
                       for category, rule_ids in mapping.items())):
        raise EvaluationError("Ground truth must include explicit category_rule_ids.")
    if not isinstance(manifest.get("pairs"), list):
        raise EvaluationError("Ground truth must contain vulnerable/fixed pairs.")
    for pair in manifest["pairs"]:
        if (not isinstance(pair, dict) or pair.get("vulnerable") not in ids
                or pair.get("fixed") not in ids or pair["vulnerable"] == pair["fixed"]
                or not isinstance(pair.get("category"), str)
                or pair.get("required_scanner") not in {"heuristic", "gitleaks", "semgrep", "osv"}):
            raise EvaluationError("Ground truth contains an invalid vulnerable/fixed pair.")
        by_id = {case["id"]: case for case in cases}
        if by_id[pair["vulnerable"]]["status"] != "vulnerable" or by_id[pair["fixed"]]["status"] != "fixed":
            raise EvaluationError("Ground truth pair members must have vulnerable/fixed statuses.")
    return manifest, manifest_path.parent


def calculate_metrics(rows: list[tuple[bool | None, bool | None]]) -> dict[str, Any]:
    """Calculate metrics, excluding inconclusive labels and unsupported predictions."""
    included = [(actual, predicted) for actual, predicted in rows
                if actual is not None and predicted is not None]
    excluded = len(rows) - len(included)
    tp = sum(actual is True and predicted is True for actual, predicted in included)
    fp = sum(actual is False and predicted is True for actual, predicted in included)
    fn = sum(actual is True and predicted is False for actual, predicted in included)
    tn = sum(actual is False and predicted is False for actual, predicted in included)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * precision * recall / (precision + recall) if precision is not None and recall is not None and precision + recall else (0.0 if precision == 0 and recall == 0 else None)
    fpr = fp / (fp + tn) if fp + tn else None
    return {"true_positives": tp, "false_positives": fp, "false_negatives": fn,
            "true_negatives": tn, "precision": precision, "recall": recall,
            "f1": f1, "false_positive_rate": fpr, "cases": len(included),
            "excluded_cases": excluded,
            "denominators": {"precision": tp + fp, "recall": tp + fn,
                             "f1_precision": tp + fp, "f1_recall": tp + fn,
                             "false_positive_rate": fp + tn}}


def _read_fixture(case: dict[str, Any], root: Path) -> list[SourceFile]:
    fixture_root = _inside(root, case["path"])
    files: list[SourceFile] = []
    for path in sorted(item for item in fixture_root.rglob("*") if item.is_file()):
        relative = path.relative_to(fixture_root).as_posix()
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise EvaluationError(f"Could not read fixture {case['id']} source text.") from exc
        files.append(SourceFile(relative, content, len(content.splitlines())))
    if not files:
        raise EvaluationError(f"Fixture {case['id']} contains no readable source files.")
    return files


def _findings_payload(findings: list[Any]) -> list[dict[str, str]]:
    # Reports intentionally retain only identifiers and paths, never evidence,
    # titles, descriptions, or scanner output that might contain a secret.
    return [{"rule_id": redact_evidence(str(getattr(item, "rule_id", ""))),
             "file_path": redact_evidence(str(getattr(item, "file_path", ""))),
             "source_scanner": redact_evidence(str(getattr(item, "source_scanner", "")))[:100]}
            for item in findings]


def _category(rule_id: str, scanner: str, mapping: dict[str, list[str]]) -> str | None:
    for category, rule_ids in mapping.items():
        if rule_id in rule_ids:
            return category
    if scanner.lower() == "gitleaks":
        return "credential"
    if scanner.lower() == "osv-scanner":
        return "dependency"
    return None


def _scanner_status(name: str, local_tools: bool) -> dict[str, Any]:
    if name == "heuristic":
        return {"availability": "built_in", "status": "pending", "reason": "Built-in scanner; always run."}
    if name == "osv":
        return {"availability": "offline_unsupported", "status": "skipped", "reason": "The existing OSV integration has no guaranteed offline database mode; network access is not used by this evaluation."}
    if not local_tools:
        return {"availability": "not_checked", "status": "not_requested", "reason": "Use --local-tools to run installed local scanner executables."}
    executable = _local_executable(name)
    if executable:
        return {"availability": "installed", "status": "pending", "reason": "Found local executable; no installation or download attempted."}
    return {"availability": "unavailable", "status": "unavailable", "reason": "Executable is not installed on PATH; no download attempted."}


def _local_executable(name: str) -> str | None:
    """Match the supported local executable lookup used by scanner adapters."""
    names = ("gitleaks", "gitleaks.exe") if name == "gitleaks" else ("semgrep", "semgrep.exe")
    for executable_name in names:
        executable = shutil.which(executable_name)
        if executable:
            return executable
    if name == "semgrep":
        for executable_name in names:
            candidate = Path(sys.executable).parent / executable_name
            if candidate.is_file():
                return str(candidate)
    return None


def run_evaluation(manifest_path: Path, output_dir: Path, *, local_tools: bool = False,
                   write_volatile_metadata: bool = True) -> dict[str, Any]:
    manifest, fixture_root = load_manifest(manifest_path)
    scanner_status = {name: _scanner_status(name, local_tools) for name in ("heuristic", "gitleaks", "semgrep", "osv")}
    errors: list[dict[str, str]] = []
    active_scanners = ["heuristic"]
    if local_tools:
        active_scanners += [name for name in ("gitleaks", "semgrep") if scanner_status[name]["status"] == "pending"]
    scans_by_case: dict[str, dict[str, list[Any]]] = {}

    for case in manifest["cases"]:
        fixture_files = _read_fixture(case, fixture_root)
        # Exercise the same archive validation and in-memory reader used by
        # uploads, without extracting fixture contents to disk.
        archive_buffer = io.BytesIO()
        with zipfile.ZipFile(archive_buffer, mode="w") as archive:
            for source_file in fixture_files:
                archive.writestr(source_file.path, source_file.content)
        files = read_repository_zip(archive_buffer.getvalue())
        if not files:
            raise EvaluationError(f"Fixture {case['id']} produced no supported archive source files.")
        findings = scan_source_files(files)
        scanner_findings = {"heuristic": findings}
        for scanner_name in active_scanners:
            if scanner_name == "heuristic":
                continue
            try:
                if scanner_name == "gitleaks":
                    from app.scanners.gitleaks import scan_with_gitleaks
                    scanner_findings[scanner_name] = scan_with_gitleaks(files)
                else:
                    from app.scanners.semgrep_scanner import scan_with_semgrep
                    scanner_findings[scanner_name] = scan_with_semgrep(files)
            except Exception as exc:  # never serialize scanner stderr/stdout
                scanner_findings[scanner_name] = []
                errors.append({"case_id": case["id"], "scanner": scanner_name,
                               "error_type": type(exc).__name__,
                               "message": "Local scanner execution failed; raw output omitted."})
        scans_by_case[case["id"]] = scanner_findings

    failed_scanners = {item["scanner"] for item in errors}
    for scanner_name in active_scanners:
        scanner_status[scanner_name]["status"] = "failed" if scanner_name in failed_scanners else "completed"
        if scanner_name in failed_scanners:
            scanner_status[scanner_name]["reason"] = "At least one fixture scan failed; this scanner's metrics are excluded."
    successful_scanners = {name for name in active_scanners if scanner_status[name]["status"] == "completed"}
    evaluated_categories = set().union(*(SCANNER_CATEGORIES[name] for name in successful_scanners))
    case_results: list[dict[str, Any]] = []
    detected_by_case: dict[str, set[str]] = {}
    detected_rule_ids_by_case: dict[str, set[str]] = {}
    for case in manifest["cases"]:
        scanner_findings = scans_by_case[case["id"]]
        mapped = set()
        public_findings = []
        for scanner_name in successful_scanners:
            for item in scanner_findings.get(scanner_name, []):
                item_scanner = str(getattr(item, "source_scanner", scanner_name))
                item_category = _category(str(getattr(item, "rule_id", "")), item_scanner,
                                          manifest["category_rule_ids"])
                if item_category:
                    mapped.add(item_category)
                public_findings.extend(_findings_payload([item]))
        detected_by_case[case["id"]] = mapped
        detected_rule_ids_by_case[case["id"]] = {item["rule_id"] for item in public_findings}
        heuristic_findings = scanner_findings.get("heuristic", [])
        case_results.append({"case_id": case["id"], "category": case["category"],
                             "status": case["status"], "files": [f.path for f in _read_fixture(case, fixture_root)],
                             "expected_rule_ids": case["expected_rule_ids"],
                             "expected_categories": case["expected_categories"],
                             "ground_truth_labels": case["labels"],
                             "detected_rule_ids": sorted(detected_rule_ids_by_case[case["id"]]),
                             "unit_rule_ids": sorted({str(getattr(item, "rule_id", "")) for item in heuristic_findings}),
                             "detected_categories": sorted(mapped),
                             "limitations": case.get("limitations", []),
                             "findings": sorted(public_findings, key=lambda item: (item["file_path"], item["rule_id"], item["source_scanner"]))})
    pair_scanners = {pair["category"]: pair["required_scanner"] for pair in manifest["pairs"]}
    required_case_failures: list[str] = []
    for case_result, case in zip(case_results, manifest["cases"]):
        checkable = {category for category, truth in case["labels"].items()
                     if truth is not None and category in evaluated_categories}
        expected_positive = {category for category in checkable if case["labels"][category] is True}
        observed_checkable = set(case_result["detected_categories"]).intersection(checkable)
        case_result["evaluated_label_categories"] = sorted(checkable)
        case_result["expected_categories_match"] = observed_checkable == expected_positive if checkable else None
        required_scanner = pair_scanners.get(case["category"])
        scanner_is_active = required_scanner is None or scanner_status[required_scanner]["status"] == "completed"
        case_result["expected_rule_ids_match"] = (
            all(rule_id in case_result["detected_rule_ids"] for rule_id in case["expected_rule_ids"])
            if case["expected_rule_ids"] and scanner_is_active else None
        )
        case_result["check_status"] = "evaluated" if checkable and scanner_is_active else "not_evaluated"
        if case_result["check_status"] == "evaluated" and case_result["expected_categories_match"] is False:
            required_case_failures.append(case["id"])
        if case_result["expected_rule_ids_match"] is False:
            required_case_failures.append(case["id"])
    metric_observations: list[dict[str, Any]] = []
    for case in manifest["cases"]:
        for category, truth in case["labels"].items():
            category_evaluated = category in evaluated_categories
            if truth is None:
                reason = "Ground truth is inconclusive for this category."
            elif not category_evaluated:
                scanners_for_category = [name for name, categories in SCANNER_CATEGORIES.items()
                                         if category in categories]
                states = [f"{name}={scanner_status[name]['status']}" for name in scanners_for_category]
                reason = "No successful scanner supports this category (" + ", ".join(states) + ")."
            else:
                reason = None
            metric_observations.append({
                "case_id": case["id"], "category": category,
                "ground_truth": truth,
                "predicted": category in detected_by_case[case["id"]] if category_evaluated else None,
                "included": truth is not None and category_evaluated,
                "exclusion_reason": reason,
            })

    metric_categories: dict[str, Any] = {}
    unit_metrics: dict[str, Any] = {}
    for category in sorted(evaluated_categories):
        rows = [(item["ground_truth"], item["predicted"])
                for item in metric_observations
                if item["category"] == category]
        metric_categories[category] = calculate_metrics(rows)
        # Individual heuristic rule result uses the same actual scanner but is
        # kept separate from aggregated full-pipeline metrics.
        if category in SCANNER_CATEGORIES["heuristic"]:
            rule_ids = [rule_id for rule_id in manifest["category_rule_ids"].get(category, [])
                        if rule_id.startswith("HEURISTIC-")]
            rule_rows = []
            for case, result in zip(manifest["cases"], case_results):
                truth = case["labels"].get(category)
                present = bool(set(result["unit_rule_ids"]).intersection(rule_ids))
                rule_rows.append((truth, present))
            unit_metrics[category] = {"rule_ids": rule_ids, **calculate_metrics(rule_rows)}

    case_by_id = {case["id"]: case for case in manifest["cases"]}
    pair_results = []
    required_failures = []
    for pair in manifest["pairs"]:
        scanner = pair["required_scanner"]
        active = scanner_status[scanner]["status"] == "completed"
        if not active:
            pair_results.append({"category": pair["category"], "vulnerable_case": pair["vulnerable"],
                                 "fixed_case": pair["fixed"], "status": "not_evaluated",
                                 "reason": f"Required scanner {scanner} was not run."})
            continue
        vuln_expected = case_by_id[pair["vulnerable"]]["labels"].get(pair["category"])
        fixed_expected = case_by_id[pair["fixed"]]["labels"].get(pair["category"])
        vuln_detected = pair["category"] in detected_by_case[pair["vulnerable"]]
        fixed_detected = pair["category"] in detected_by_case[pair["fixed"]]
        passed = vuln_expected is True and fixed_expected is False and vuln_detected and not fixed_detected
        if not passed:
            required_failures.append(pair["category"])
        pair_results.append({"category": pair["category"], "vulnerable_case": pair["vulnerable"],
                             "fixed_case": pair["fixed"], "vulnerable_target_detected": vuln_detected,
                             "fixed_target_absent": not fixed_detected, "status": "passed" if passed else "failed",
                             "unexpected_vulnerable_findings": sorted(detected_by_case[pair["vulnerable"]] - {pair["category"]}),
                             "remaining_fixed_findings": sorted(detected_by_case[pair["fixed"]] - {pair["category"]})})

    not_evaluated_categories = {}
    all_categories = set(manifest["category_rule_ids"])
    for case in manifest["cases"]:
        all_categories.update(case["labels"])
    for category in sorted(all_categories - evaluated_categories):
        supporting = [name for name, categories in SCANNER_CATEGORIES.items()
                      if category in categories]
        not_evaluated_categories[category] = {
            "reason": "No successful scanner supports this category.",
            "supporting_scanners": {name: scanner_status[name]["status"] for name in supporting},
        }

    result = {
        "dataset_version": manifest.get("dataset_version"),
        "evaluation_version": "1.0.0",
        "mode": "local-tools" if local_tools else "offline-default",
        "matching": "Exact rule-ID mapping to explicit categories; Gitleaks source maps to credential, OSV-Scanner source maps to dependency. Each metric observation is one fixture/category pair. Only boolean ground truth with a successful supporting scanner is included; inconclusive labels and unsupported/failed scanner categories are excluded.",
        "scanner_status": scanner_status,
        "evaluated_categories": sorted(evaluated_categories),
        "unit_rule_metrics": unit_metrics,
        "full_pipeline_metrics": {"per_category": metric_categories,
                                   "overall": calculate_metrics([])},
        "metric_observations": metric_observations,
        "not_evaluated_categories": not_evaluated_categories,
        "cases": case_results,
        "vulnerable_fixed_pairs": pair_results,
        "required_pair_failures": required_failures,
        "required_case_failures": sorted(set(required_case_failures)),
        "scanner_errors": errors,
        "limitations": ["A small synthetic dataset does not establish production security effectiveness.",
                        "Code fixtures are scanned as text and never executed.",
                        "OSV dependency findings are not scored because the current integration does not guarantee offline operation.",
                        "Precision, recall, F1, and false-positive rate describe this fixture set only; undefined denominators are null."],
    }
    # Overall metrics count each labeled case-category pair once.
    overall_rows = [(item["ground_truth"], item["predicted"])
                    for item in metric_observations]
    result["full_pipeline_metrics"]["overall"] = calculate_metrics(overall_rows)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "results.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output_dir / "report.md").write_text(render_markdown(result), encoding="utf-8")
    if write_volatile_metadata:
        metadata = {"generated_at_utc": datetime.now(timezone.utc).isoformat(),
                    "dataset_version": manifest.get("dataset_version"),
                    "mode": result["mode"]}
        (output_dir / "run-metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if errors or required_failures or required_case_failures:
        raise EvaluationError("Evaluation completed with scanner errors or failed required pairs; inspect results.json.")
    return result


def render_markdown(result: dict[str, Any]) -> str:
    lines = ["# RepoSentinel synthetic security evaluation", "",
             f"Dataset version: `{result['dataset_version']}`  ",
             f"Mode: `{result['mode']}`", "",
             "Small synthetic results do not establish production security effectiveness.", "",
             "## Metric definitions", "",
             "The unit of analysis is one fixture/category pair, not one finding. TP: positive label and detected; FP: negative label and detected; FN: positive label and not detected; TN: negative label and not detected. Precision denominator = TP+FP; recall denominator = TP+FN; F1 is the harmonic mean of precision and recall; false-positive-rate denominator = FP+TN. Undefined metric denominators are `null`. `cases` counts included observations; `excluded_cases` counts inconclusive labels or categories without a successful supporting scanner. The JSON `metric_observations` list records ground truth, prediction, inclusion, and exclusion reason for independent recalculation.", "",
             "## Scanner availability", "", "| Scanner | Status | Reason |", "|---|---|---|"]
    for name, status in sorted(result["scanner_status"].items()):
        lines.append(f"| {name} | {status['status']} | {status['reason']} |")
    lines += ["", "## Unit-level rule metrics", "", "| Category | Rule IDs | N included | Excluded | TP | FP | FN | TN | Precision | Recall | F1 | FPR |", "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for category, metrics in sorted(result["unit_rule_metrics"].items()):
        lines.append(_metric_row(category, metrics))
    lines += ["", "## Full-pipeline metrics by category", "", "| Category | N included | Excluded | TP | FP | FN | TN | Precision | Recall | F1 | FPR |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for category, metrics in sorted(result["full_pipeline_metrics"]["per_category"].items()):
        lines.append(_metric_row(category, metrics))
    lines += ["", "## Categories not evaluated", "", "| Category | Supporting scanner status | Reason |", "|---|---|---|"]
    for category, detail in sorted(result["not_evaluated_categories"].items()):
        scanner_states = ", ".join(f"{name}: {status}" for name, status in sorted(detail["supporting_scanners"].items())) or "no mapped scanner"
        lines.append(f"| {category} | {scanner_states} | {detail['reason']} |")
    lines += ["", "## Overall full-pipeline metrics", "", "```json", json.dumps(result["full_pipeline_metrics"]["overall"], sort_keys=True), "```", "", "## Vulnerable versus fixed", "", "| Category | Vulnerable target detected | Fixed target absent | Result |", "|---|---:|---:|---|"]
    for pair in result["vulnerable_fixed_pairs"]:
        if pair["status"] == "not_evaluated":
            lines.append(f"| {pair['category']} | n/a | n/a | Not evaluated: {pair['reason']} |")
        else:
            lines.append(f"| {pair['category']} | {pair['vulnerable_target_detected']} | {pair['fixed_target_absent']} | {pair['status']} |")
    lines += ["", "## Cases", "", "| Fixture | Ground truth | Category | Expected rule IDs | Detected rule IDs | Unexpected categories | Limitations |", "|---|---|---|---|---|---|---|"]
    for case in result["cases"]:
        unexpected = sorted(set(case["detected_categories"]) - {case["category"], "benign"})
        lines.append(f"| {case['case_id']} | {case['status']} | {case['category']} | {', '.join(case['expected_rule_ids']) or 'none'} | {', '.join(case['detected_rule_ids']) or 'none'} | {', '.join(unexpected) or 'none'} | {'; '.join(case['limitations']) or 'none'} |")
    lines += ["", "## Limitations and errors", ""]
    lines.extend(f"- {item}" for item in result["limitations"])
    lines.extend(f"- Scanner error: {item['case_id']} / {item['scanner']} ({item['error_type']}); details omitted." for item in result["scanner_errors"])
    return "\n".join(lines) + "\n"


def _metric_row(category: str, metric: dict[str, Any]) -> str:
    if "rule_ids" in metric:
        return f"| {category} | {', '.join(metric['rule_ids'])} | {metric['cases']} | {metric['excluded_cases']} | {metric['true_positives']} | {metric['false_positives']} | {metric['false_negatives']} | {metric['true_negatives']} | {metric['precision']} | {metric['recall']} | {metric['f1']} | {metric['false_positive_rate']} |"
    return f"| {category} | {metric['cases']} | {metric['excluded_cases']} | {metric['true_positives']} | {metric['false_positives']} | {metric['false_negatives']} | {metric['true_negatives']} | {metric['precision']} | {metric['recall']} | {metric['f1']} | {metric['false_positive_rate']} |"


def main() -> int:
    import argparse

    project = Path(__file__).resolve().parents[2]
    default_manifest = project / "tests" / "evaluation" / "manifest.json"
    parser = argparse.ArgumentParser(description="Run RepoSentinel's bundled synthetic evaluation.")
    parser.add_argument("--manifest", type=Path, default=default_manifest)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--local-tools", action="store_true",
                        help="Run installed Gitleaks and Semgrep using local integrations; never download tools.")
    args = parser.parse_args()
    output_dir = args.output or project / "evaluation-results" / ("local-tools" if args.local_tools else "offline-default")
    try:
        result = run_evaluation(args.manifest, output_dir, local_tools=args.local_tools)
    except EvaluationError as exc:
        print(f"Evaluation failed: {exc}")
        return 1
    except Exception:
        print("Evaluation failed due to an unexpected internal error; raw scanner output was omitted.")
        return 1
    print(f"Evaluation complete: {output_dir / 'results.json'}")
    print(f"Markdown report: {output_dir / 'report.md'}")
    print(f"Required pair failures: {len(result['required_pair_failures'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
