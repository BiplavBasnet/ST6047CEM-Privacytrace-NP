from typing import TYPE_CHECKING

from sqlalchemy import Enum, Float, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import Severity

if TYPE_CHECKING:
    from app.models.evidence_file import EvidenceFile


class SecretFinding(Base):
    __tablename__ = "secret_findings"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    evidence_id: Mapped[str] = mapped_column(
        ForeignKey("evidence_files.evidence_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    secret_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    masked_secret: Mapped[str] = mapped_column(String(512), nullable=False)
    severity: Mapped[Severity | None] = mapped_column(
        Enum(Severity, name="secret_severity", native_enum=False),
        nullable=True,
    )
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)

    evidence_file: Mapped["EvidenceFile"] = relationship(
        "EvidenceFile",
        back_populates="secret_findings",
    )
