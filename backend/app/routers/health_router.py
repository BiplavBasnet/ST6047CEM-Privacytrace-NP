from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.database import check_database_connection

router = APIRouter(tags=["health"])


@router.get("/health")
def health_check():
    settings = get_settings()
    db_ok = check_database_connection()

    body = {
        "status": "healthy" if db_ok else "unhealthy",
        "service": settings.service_name,
        "database": "connected" if db_ok else "disconnected",
        "version": settings.api_version,
    }

    if not db_ok:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=body,
        )

    return body
