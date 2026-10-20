import json
from pathlib import Path

import pytest

from app.core.evaluation import (
    EvaluationError,
    calculate_metrics,
    load_manifest,
    run_evaluation,
)


EVALUATION_ROOT = Path(__file__).parent / "evaluation"


def test_manifest_validates_all_bundled_fixtures():
    manifest, root = load_manifest(EVALUATION_ROOT / "manifest.json")
    assert manifest["dataset_version"] == "1.0.0"
    assert len(manifest["cases"]) >= 10
    assert (root / "fixtures" / "credential" / "vulnerable").is_dir()


def test_invalid_manifest_path_is_rejected(tmp_path):
    manifest = {
        "cases": [{"id": "escape", "path": "../../outside", "status": "negative",
                   "expected_rule_ids": [], "labels": {}}],
        "category_rule_ids": {"credential": []}, "pairs": [],
    }
    source = tmp_path / "manifest.json"
    source.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(EvaluationError):
        load_manifest(source)


def test_metric_denominators_return_null_when_undefined():
    empty = calculate_metrics([])
    assert empty["precision"] is None
    assert empty["recall"] is None
    assert empty["f1"] is None
    assert empty["false_positive_rate"] is None
    no_positive_predictions = calculate_metrics([(True, False), (False, False)])
    assert no_positive_predictions["precision"] is None
    assert no_positive_predictions["recall"] == 0


def test_inconclusive_and_unsupported_metric_rows_are_excluded():
    metrics = calculate_metrics([
        (True, True),
        (False, False),
        (None, False),  # Inconclusive ground truth must not become a TN.
        (True, None),   # Unsupported scanner result must not become a FN.
    ])
    assert metrics["true_positives"] == 1
    assert metrics["true_negatives"] == 1
    assert metrics["false_positives"] == metrics["false_negatives"] == 0
    assert metrics["cases"] == 2
    assert metrics["excluded_cases"] == 2
    assert metrics["denominators"] == {
        "precision": 1, "recall": 1, "f1_precision": 1,
        "f1_recall": 1, "false_positive_rate": 1,
    }


def test_bundled_evaluation_detects_rule_positives_and_fixed_pairs_deterministically(tmp_path):
    manifest_path = EVALUATION_ROOT / "manifest.json"
    first_dir, second_dir = tmp_path / "first", tmp_path / "second"
    first = run_evaluation(manifest_path, first_dir, write_volatile_metadata=False)
    second = run_evaluation(manifest_path, second_dir, write_volatile_metadata=False)
    assert first["unit_rule_metrics"]["credential"]["true_positives"] == 1
    assert first["unit_rule_metrics"]["debug"]["true_positives"] == 1
    assert first["unit_rule_metrics"]["tls"]["true_positives"] == 1
    assert first["unit_rule_metrics"]["sql_concat"]["true_positives"] == 1
    assert all(pair["status"] == "passed" for pair in first["vulnerable_fixed_pairs"] if pair["category"] in {"credential", "debug", "tls", "sql_concat"})
    assert first["scanner_status"]["osv"]["status"] == "skipped"
    assert first["full_pipeline_metrics"]["overall"]["cases"] == 36
    assert first["full_pipeline_metrics"]["overall"]["excluded_cases"] == 4
    assert first["not_evaluated_categories"]["dynamic_code"]["supporting_scanners"]["semgrep"] == "not_requested"
    assert first["not_evaluated_categories"]["dependency"]["supporting_scanners"]["osv"] == "skipped"
    assert (first_dir / "results.json").read_bytes() == (second_dir / "results.json").read_bytes()
    assert (first_dir / "report.md").read_bytes() == (second_dir / "report.md").read_bytes()
    assert "DEMO_EXAMPLE_KEY_12345" not in (first_dir / "results.json").read_text(encoding="utf-8")
    assert "DEMO_EXAMPLE_KEY_12345" not in (first_dir / "report.md").read_text(encoding="utf-8")
    # Independently reproduce the full-pipeline overall and per-category
    # confusion matrices from serialized, included observations.
    observations = json.loads((first_dir / "results.json").read_text(encoding="utf-8"))["metric_observations"]

    def independent_counts(rows):
        return {
            "true_positives": sum(row["ground_truth"] is True and row["predicted"] is True for row in rows),
            "false_positives": sum(row["ground_truth"] is False and row["predicted"] is True for row in rows),
            "false_negatives": sum(row["ground_truth"] is True and row["predicted"] is False for row in rows),
            "true_negatives": sum(row["ground_truth"] is False and row["predicted"] is False for row in rows),
        }

    included = [row for row in observations if row["included"]]
    overall = first["full_pipeline_metrics"]["overall"]
    assert independent_counts(included) == {key: overall[key] for key in (
        "true_positives", "false_positives", "false_negatives", "true_negatives")}
    for category, category_metrics in first["full_pipeline_metrics"]["per_category"].items():
        category_rows = [row for row in observations if row["category"] == category and row["included"]]
        assert independent_counts(category_rows) == {key: category_metrics[key] for key in (
            "true_positives", "false_positives", "false_negatives", "true_negatives")}
    inconclusive_dependency = next(row for row in observations if row["category"] == "dependency")
    assert inconclusive_dependency["ground_truth"] is None
    assert inconclusive_dependency["included"] is False
    unsupported_dynamic = next(row for row in observations if row["category"] == "dynamic_code")
    assert unsupported_dynamic["predicted"] is None
    assert unsupported_dynamic["included"] is False


def test_fixed_pair_reports_target_separately_from_unrelated_findings(tmp_path):
    output = run_evaluation(EVALUATION_ROOT / "manifest.json", tmp_path / "evaluation", write_volatile_metadata=False)
    sql_pair = next(pair for pair in output["vulnerable_fixed_pairs"] if pair["category"] == "sql_concat")
    assert sql_pair["fixed_target_absent"] is True
    assert isinstance(sql_pair["remaining_fixed_findings"], list)


def test_missing_local_scanners_are_reported_not_treated_as_success(monkeypatch, tmp_path):
    import app.core.evaluation as evaluation

    monkeypatch.setattr(evaluation, "_local_executable", lambda _name: None)
    result = run_evaluation(EVALUATION_ROOT / "manifest.json", tmp_path / "out", local_tools=True,
                           write_volatile_metadata=False)
    assert result["scanner_status"]["gitleaks"]["status"] == "unavailable"
    assert result["scanner_status"]["semgrep"]["status"] == "unavailable"
    assert "dynamic_code" not in result["full_pipeline_metrics"]["per_category"]
    assert next(pair for pair in result["vulnerable_fixed_pairs"] if pair["category"] == "dynamic_code")["status"] == "not_evaluated"


def test_local_scanner_errors_are_recorded_without_raw_output(monkeypatch, tmp_path):
    import app.core.evaluation as evaluation
    import app.scanners.gitleaks as gitleaks

    secret = "SYNTH_SCANNER_STDERR_SECRET_123"
    monkeypatch.setattr(evaluation, "_local_executable", lambda name: "local-gitleaks" if name == "gitleaks" else None)

    def scanner_failure(_files):
        raise RuntimeError(f"scanner output had {secret}")

    monkeypatch.setattr(gitleaks, "scan_with_gitleaks", scanner_failure)
    out = tmp_path / "out"
    with pytest.raises(EvaluationError):
        run_evaluation(EVALUATION_ROOT / "manifest.json", out, local_tools=True,
                       write_volatile_metadata=False)
    serialized = (out / "results.json").read_text(encoding="utf-8")
    assert "RuntimeError" in serialized
    assert secret not in serialized
    error_report = json.loads(serialized)
    assert error_report["scanner_status"]["gitleaks"]["status"] == "failed"
    # --local-tools requests both external scanners. Semgrep was requested but
    # no local executable was found, so it is unavailable (not not_requested).
    assert error_report["not_evaluated_categories"]["dynamic_code"]["supporting_scanners"]["semgrep"] == "unavailable"


def test_failed_semgrep_does_not_score_dynamic_code_as_a_miss(monkeypatch, tmp_path):
    import app.core.evaluation as evaluation
    import app.scanners.semgrep_scanner as semgrep

    monkeypatch.setattr(evaluation, "_local_executable", lambda name: "local-semgrep" if name == "semgrep" else None)

    def failed_scan(_files):
        raise RuntimeError("local semgrep failed")

    monkeypatch.setattr(semgrep, "scan_with_semgrep", failed_scan)
    output_dir = tmp_path / "local"
    with pytest.raises(EvaluationError):
        run_evaluation(EVALUATION_ROOT / "manifest.json", output_dir, local_tools=True,
                       write_volatile_metadata=False)
    result = json.loads((output_dir / "results.json").read_text(encoding="utf-8"))
    assert result["scanner_status"]["semgrep"]["status"] == "failed"
    assert "dynamic_code" not in result["full_pipeline_metrics"]["per_category"]
    assert result["not_evaluated_categories"]["dynamic_code"]["supporting_scanners"]["semgrep"] == "failed"
    dynamic_pair = next(pair for pair in result["vulnerable_fixed_pairs"] if pair["category"] == "dynamic_code")
    assert dynamic_pair["status"] == "not_evaluated"
