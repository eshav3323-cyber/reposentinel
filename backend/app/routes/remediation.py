
from fastapi import APIRouter, HTTPException, Query

from app.core.attack_graph import build_attack_graph
from app.core.remediation import build_remediation_plan
from app.models.remediation import RemediationResponse
from app.routes.scans import find_scan

router = APIRouter(tags=["Remediation"])


@router.get(
    "/api/scans/{scan_id}/remediation",
    response_model=RemediationResponse,
)
def get_scan_remediation(
    scan_id: str,
    budget: int = Query(default=5, ge=1, le=25),
):
    result = find_scan(scan_id)

    if result is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found. It may have expired or been deleted.",
        )

    findings = result.get("findings", [])
    graph = build_attack_graph(scan_id=scan_id, findings=findings)

    return build_remediation_plan(
        scan_id=scan_id,
        findings=findings,
        graph=graph,
        budget=budget,
    )
