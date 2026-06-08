from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.incident import Incident


class LlmReport(Base):
    __tablename__ = "llm_reports"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    report_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provider_used: Mapped[str] = mapped_column(String(32), nullable=False)
    model_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    input_context_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    output_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    output_encrypted: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    output_crypto_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    is_encrypted: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    safety_status: Mapped[str] = mapped_column(String(32), nullable=False)
    validation_errors: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    incident: Mapped["Incident"] = relationship(
        "Incident",
        back_populates="llm_reports",
    )
