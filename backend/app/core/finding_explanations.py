import re
from typing import Any

from app.models.findings import Finding, FindingExplanation


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _keyword_present(*values: Any) -> bool:
    haystack = " ".join(_as_text(value).lower() for value in values if _as_text(value))
    return bool(haystack)


def build_finding_explanation(finding: Finding | dict[str, Any]) -> FindingExplanation:
    """Return a human-readable explanation for a normalized vulnerability."""

    if isinstance(finding, Finding):
        payload = finding.model_dump()
    else:
        payload = dict(finding)

    title = _as_text(payload.get("title") or payload.get("rule_id") or "Security finding")
    rule_id = _as_text(payload.get("rule_id") or "")
    description = _as_text(payload.get("description") or "")
    evidence = _as_text(payload.get("redacted_evidence") or payload.get("evidence") or "")
    file_path = _as_text(payload.get("file_path") or "")
    severity = _as_text(payload.get("severity") or "medium").lower()
    combined_text = " ".join(
        part for part in [title, rule_id, description, evidence, file_path] if part
    ).lower()

    def fallback() -> FindingExplanation:
        impact = [
            "The actual impact depends on whether the affected code path is reachable and whether the application is exposed to the relevant traffic or users.",
            "This issue should be reviewed in context before treating it as a confirmed exploit or a live security breach.",
        ]
        fix_steps = [
            "Review the exact file and line the scanner flagged.",
            "Apply the technical remediation shown in the security details and confirm the change with a focused review.",
            "Retest the affected feature or dependency after the fix to confirm the risk has been reduced.",
        ]
        return FindingExplanation(
            simple_title="Potential security issue",
            what_it_means=(
                "This finding points to a code pattern, setting, or dependency that may create a security weakness. "
                "The scanner flagged it for human review, which means it needs a real check rather than an automatic assumption."
            ),
            why_it_matters=(
                "Even a small weakness can make an application easier to attack or harder to protect. "
                "The practical risk depends on how the code is used and whether the vulnerable path is reachable."
            ),
            possible_impact=impact,
            how_to_fix=fix_steps,
        )

    secret_patterns = (
        "secret",
        "credential",
        "token",
        "password",
        "api key",
        "private key",
        "auth token",
        "bearer",
        "access token",
    )
    if any(pattern in combined_text for pattern in secret_patterns):
        return FindingExplanation(
            simple_title="Sensitive information appears to be stored in code",
            what_it_means=(
                "This issue means a password, API key, token, or similar secret appears to be placed directly in the code. "
                "That makes the secret easier to copy or discover if someone obtains the repository or its history."
            ),
            why_it_matters=(
                "Secrets should not live in source files because they may leak through backups, logs, screenshots, pull requests, or shared environments. "
                "Once exposed, the secret may be reused outside the intended application."
            ),
            possible_impact=[
                "An attacker may reuse a stolen credential to access an external service or system.",
                "The application may lose access to required services or experience unexpected outages if the exposed secret is revoked.",
            ],
            how_to_fix=[
                "Move the secret to a proper secret manager or environment variable provided at runtime.",
                "Rotate or revoke the secret if it is real and may already be exposed.",
                "Remove the hardcoded value from the code, commit history, and any copied configuration files before deployment.",
            ],
        )

    dependency_markers = (
        "package:",
        "dependency",
        "vulnerable dependency",
        "osv",
        "known vulnerability",
        "affected package",
        "package version",
    )
    if any(marker in combined_text for marker in dependency_markers) or re.search(r"cve|ghsa|osv-[a-z0-9-]+", rule_id, re.IGNORECASE):
        package_name = ""
        package_match = re.search(r"Package:\s*([A-Za-z0-9_.\-/]+)", description, re.IGNORECASE)
        if package_match:
            package_name = package_match.group(1)

        package_title = f"{package_name} has a known vulnerability" if package_name else "A dependency in this project has a known security issue"
        return FindingExplanation(
            simple_title=package_title,
            what_it_means=(
                "This finding means the project has a dependency on an external software component that has a known weakness. "
                "A security advisory or scanner has identified that this installed package version may be vulnerable."
            ),
            why_it_matters=(
                "Dependency weaknesses can be exploited when an attacker reaches the affected code path or service. "
                "The risk may be low or high depending on how the package is used and whether it is exposed to untrusted input."
            ),
            possible_impact=[
                "An attacker may abuse the known weakness if the vulnerable component is reachable through your application or deployment.",
                "The actual impact can range from reduced security to a full compromise, depending on the dependency and its usage.",
            ],
            how_to_fix=[
                "Check the package advisory and update the dependency to a patched version that is listed as fixed.",
                "Review the app's compatibility requirements before upgrading so the fix does not introduce regressions.",
                "Retest the application after the upgrade and keep dependency versions current in your dependency management files.",
            ],
        )

    if any(marker in combined_text for marker in ("debug", "tls", "ssl", "sql", "unsafe", "verify = false", "certificate verification", "sql injection", "insecure", "authentication", "authorization")):
        return FindingExplanation(
            simple_title="The code contains a risky configuration or unsafe pattern",
            what_it_means=(
                "This issue means the code or configuration is using a pattern that can weaken security or make it easier to misuse the application. "
                "Examples include disabling TLS verification, allowing unsafe database queries, or enabling a setting that should stay protected."
            ),
            why_it_matters=(
                "Unsafe configuration and risky code patterns can create openings for abuse, especially when the affected feature is reachable from users or external systems. "
                "These issues often become much more serious when combined with other weaknesses."
            ),
            possible_impact=[
                "A user or attacker may be able to trigger the weak behavior and change application outcomes that should be controlled.",
                "The exact impact depends on the affected feature, its exposure, and whether the vulnerable path is reachable in real use.",
            ],
            how_to_fix=[
                "Review the exact file, function, and setting named by the scanner.",
                "Change the risky configuration to a secure default and keep the fix specific to the actual root cause.",
                "Retest the relevant workflow and confirm the application still behaves correctly after the security change.",
            ],
        )

    if any(marker in combined_text for marker in ("patient", "medical", "health", "healthcare", "care record", "records")):
        return FindingExplanation(
            simple_title="The application may expose sensitive healthcare information too broadly",
            what_it_means=(
                "This issue is tied to data access or protection around health-related records or patient information. "
                "The scanner is flagging a condition that may allow data to be accessed, exposed, or handled more broadly than intended."
            ),
            why_it_matters=(
                "Health and patient information is especially sensitive because it can affect privacy, trust, and compliance requirements. "
                "Even a small access-control issue can become significant if it exposes or allows wider access than intended."
            ),
            possible_impact=[
                "An unauthorized user might be able to view or manipulate sensitive records if the weakness is reachable in the running application.",
                "The issue may not prove active exposure yet, but it still needs prompt review because the impact could be serious.",
            ],
            how_to_fix=[
                "Verify who is allowed to access the affected endpoint, data source, or resource.",
                "Restrict access to the minimum required role or permission and validate the authorization check.",
                "Review audit logs, test the restricted flow, and document the final access-control decision before release.",
            ],
        )

    if any(marker in combined_text for marker in ("permission", "privilege", "role", "access control", "excessive")):
        return FindingExplanation(
            simple_title="A component may have more access than it needs",
            what_it_means=(
                "This finding suggests a user, service, or system component may have access rights that are broader than necessary. "
                "The scanner is flagging a permission pattern that could be excessive or too easy to misuse."
            ),
            why_it_matters=(
                "When permissions are broader than required, a mistake or attack can affect more of the system than intended. "
                "This increases the impact of any compromised account or injected code path."
            ),
            possible_impact=[
                "A misconfigured or compromised component might be able to read, modify, or delete more data than it should.",
                "The exact impact depends on what the account or service is allowed to access in the application environment.",
            ],
            how_to_fix=[
                "Review the relevant role, permission, or service identity and reduce access to the minimum required.",
                "Confirm that the application uses the least-privilege pattern and that unused permissions are removed.",
                "Verify the final configuration in a test environment and document the reason for each permission.",
            ],
        )

    if not evidence:
        return FindingExplanation(
            simple_title="Potential security issue",
            what_it_means=(
                "This finding was detected by the scanner, but the available evidence is limited. "
                "It still needs a human review to confirm the exact risk and its context."
            ),
            why_it_matters=(
                "Missing evidence does not make the issue harmless, but it does mean the true risk cannot be fully assessed from the metadata alone."
            ),
            possible_impact=[
                "The final impact may be higher or lower depending on how the affected code or service is used in practice.",
                "Because the evidence is incomplete, you should not treat this as a confirmed exploitation event.",
            ],
            how_to_fix=[
                "Open the exact file and review the flagged code or configuration in context.",
                "Confirm whether the issue is real, reachable, and relevant to the running application before changing production code.",
                "Document the decision and keep a record of any exception or fix that is applied.",
            ],
        )

    return fallback()
