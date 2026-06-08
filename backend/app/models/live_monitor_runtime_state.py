from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base

DEFAULT_STATE_KEY = "default"


class LiveMonitorRuntimeState(Base):
    """Durable Live Privacy Monitor control-plane state (see docs/LIVE_CORRELATION_MODEL.md).

    Historically `live_monitor_config_service` held this state only in a
    process-local dataclass (`LiveMonitorState`), so a process restart always
    reported the monitor as stopped and reset all counters, even if it had
    been started moments earlier. This is a single logical row (keyed by
    `state_key`, default `"default"`) that the service reads/writes so the
    control state survives restarts; a future multi-instance deployment could
    key additional rows by a real service/instance name.
    """

    __tablename__ = "live_monitor_runtime_state"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    state_key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, default=DEFAULT_STATE_KEY)
    running: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    mode: Mapped[str] = mapped_column(String(64), nullable=False, default="http_ingestion", server_default="http_ingestion")
    source_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    environment: Mapped[str | None] = mapped_column(String(64), nullable=True, default="demo")
    safe_mode: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")
    safety_status: Mapped[str] = mapped_column(String(32), nullable=False, default="safe", server_default="safe")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    stopped_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_event_received_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_alert_created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    alert_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    session_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
