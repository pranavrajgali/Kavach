from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from kavach_ai.backend.app.services.investigation_planner import InvestigationPlan, generate_investigation_plan


router = APIRouter(prefix="/api", tags=["GenAI investigation"])


class InvestigationPlanRequest(BaseModel):
    static_results: dict[str, Any] = Field(default_factory=dict)
    telemetry: dict[str, Any] = Field(default_factory=dict)


@router.post("/investigation-plan", response_model=InvestigationPlan)
async def create_investigation_plan(request: InvestigationPlanRequest) -> InvestigationPlan:
    """Generate a reviewable, evidence-bounded next-step sandbox plan."""
    return generate_investigation_plan(request.static_results, request.telemetry)
