from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from portal.dependencies import get_current_user, get_moodle_db
from portal.models import PortalStudent
from portal.schemas import StatsResponse
from portal import moodle_queries

stats_router = APIRouter(tags=["Portal Stats"])


@stats_router.get("/stats", response_model=StatsResponse)
def get_stats(
    current_user: PortalStudent = Depends(get_current_user),
    moodle_db: Session = Depends(get_moodle_db),
):
    """Return aggregate credential counts for the student dashboard."""
    counts = moodle_queries.count_credentials_by_status(
        moodle_db, current_user.moodle_user_id
    )

    pending = counts.get("pending", 0)
    issued = counts.get("issued", 0)
    claimed = counts.get("claimed", 0)

    return StatsResponse(
        total_credentials=pending + issued + claimed,
        pending=pending,
        issued=issued,
        claimed=claimed,
    )
