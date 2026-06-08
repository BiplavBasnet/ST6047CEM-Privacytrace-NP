from typing import TYPE_CHECKING

from sqlalchemy import Enum, Float, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import Severity

if TYPE_CHECKING:
    from app.models.evidence_file import EvidenceFile


class DependencyRisk(Base):
    __tablename__ = "dependency_risks"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    evidence_id: Mapped[str] = mapped_column(
        ForeignKey("evidence_files.evidence_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    package_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ecosystem: Mapped[str | None] = mapped_column(String(64), nullable=True)
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    risk_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    severity: Mapped[Severity | None] = mapped_column(
        Enum(Severity, name="dependency_severity", native_enum=False),
        nullable=True,
    )
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    incident_relevance: Mapped[str | None] = mapped_column(String(255), nullable=True)

    evidence_file: Mapped["EvidenceFile"] = relationship(
        "EvidenceFile",
        back_populates="dependency_risks",
    )
