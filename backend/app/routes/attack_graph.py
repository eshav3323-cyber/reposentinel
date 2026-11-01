
from fastapi import APIRouter, HTTPException

from app.core.attack_graph import build_attack_graph
from app.models.attack_graph import AttackGraphResponse
from app.routes.scans import find_scan

router = APIRouter(tags=["Attack Graph"])


@router.get(
    "/api/scans/{scan_id}/attack-graph",
    response_model=AttackGraphResponse,
)
def get_attack_graph(scan_id: str):
    result = find_scan(scan_id)

    if result is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found. It may have expired or been deleted.",
        )

    return build_attack_graph(
        scan_id=scan_id,
        findings=result.get("findings", []),
    )
