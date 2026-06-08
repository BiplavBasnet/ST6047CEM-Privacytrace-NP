from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, Index, String, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class IntegrationEvent(Base):
    """Durable, safe-only record of an ingested Universal Integration Gateway event.

    Historically `siem_import_service` only cached the canonical safe event
    view in an in-process `OrderedDict` (`_INTEGRATION_EVENT_STORE`), so
    `GET /integrations/events/{id}` returned 404 after any process restart
    even though the event had been "accepted". This table is the durable
    backing store; the OrderedDict remains as a read-through cache only (see
    docs/LIVE_CORRELATION_MODEL.md). Every column here mirrors a field already
    present on the safe in-memory record — no raw payload or raw value is
    ever persisted.
    """

    __tablename__ = "integration_events"
    __table_args__ = (
        Index(
            "uq_integration_events_source_client_event",
            "source_name",
            "client_event_id",
            unique=True,
            postgresql_where=text("client_event_id IS NOT NULL AND source_name IS NOT NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    integration_event_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    client_event_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False)
    source_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_tool: Mapped[str | None] = mapped_column(String(128), nullable=True)
    source_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source_format: Mapped[str] = mapped_column(String(64), nullable=False)
    external_alert_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    external_incident_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    event_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    service_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    endpoint: Mapped[str | None] = mapped_column(String(512), nullable=True)
    environment: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    sensitive_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    masked_value: Mapped[str | None] = mapped_column(String(512), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    message_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_reference: Mapped[str | None] = mapped_column(String(64), nullable=True)
    trace_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    trace_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    correlation_fingerprint_method: Mapped[str | None] = mapped_column(String(32), nullable=True)
    correlation_fingerprint_version: Mapped[str | None] = mapped_column(String(16), nullable=True)
    source_time_quality: Mapped[str] = mapped_column(String(32), nullable=False, default="inferred", server_default="inferred")
    source_time_inferred: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")
    source_timezone_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tags: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    raw_payload_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    safety_status: Mapped[str] = mapped_column(String(32), nullable=False, default="safe")
    sensitive_types: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    masked_values: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    correlation_keys: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    linked_alert_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    linked_incident_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    missing_metadata: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    recommendations: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    correlation_strength: Mapped[str | None] = mapped_column(String(32), nullable=True)
    warning: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
