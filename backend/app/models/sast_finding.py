from typing import TYPE_CHECKING

from sqlalchemy import Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import Severity

if TYPE_CHECKING:
    from app.models.evidence_file import EvidenceFile


class SastFinding(Base):
    __tablename__ = "sast_findings"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    evidence_id: Mapped[str] = mapped_column(
        ForeignKey("evidence_files.evidence_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    rule_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    line_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    finding_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[Severity | None] = mapped_column(
        Enum(Severity, name="sast_severity", native_enum=False),
        nullable=True,
    )
    endpoint_hint: Mapped[str | None] = mapped_column(String(512), nullable=True)

    evidence_file: Mapped["EvidenceFile"] = relationship(
        "EvidenceFile",
        back_populates="sast_findings",
    )
