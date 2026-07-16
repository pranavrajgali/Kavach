from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlmodel import Field as SQLField, Relationship, SQLModel, JSON, UniqueConstraint

# SQLModel Database Models in BCNF (Boyce-Codd Normal Form)

class APK(SQLModel, table=True):
    __tablename__ = "apks"

    apk_hash: str = SQLField(primary_key=True, max_length=64)
    filename: str = SQLField(max_length=255, nullable=False)
    file_size: int = SQLField(sa_column_kwargs={"type_": "BIGINT"}, nullable=False)
    triage_score: float = SQLField(nullable=False)
    final_score: Optional[int] = SQLField(default=None, nullable=True)
    uploaded_at: datetime = SQLField(default_factory=datetime.utcnow, nullable=False)

    # Relationships
    slices: List["SmaliSlice"] = Relationship(back_populates="apk", cascade_delete=True)
    report: Optional["CertInReport"] = Relationship(back_populates="apk", cascade_delete=True)


class SmaliSlice(SQLModel, table=True):
    __tablename__ = "smali_slices"

    slice_id: Optional[int] = SQLField(default=None, primary_key=True)
    apk_hash: str = SQLField(foreign_key="apks.apk_hash", max_length=64, nullable=False, ondelete="CASCADE")
    slice_text: str = SQLField(nullable=False)
    source_method: str = SQLField(max_length=255, nullable=False)
    probability_score: float = SQLField(nullable=False)

    # Relationships
    apk: APK = Relationship(back_populates="slices")
    attributions: List["ShapAttribution"] = Relationship(back_populates="slice", cascade_delete=True)


class ShapAttribution(SQLModel, table=True):
    __tablename__ = "shap_attributions"
    __table_args__ = (
        UniqueConstraint("slice_id", "token", name="uq_slice_token"),
    )

    attribution_id: Optional[int] = SQLField(default=None, primary_key=True)
    slice_id: int = SQLField(foreign_key="smali_slices.slice_id", nullable=False, ondelete="CASCADE")
    token: str = SQLField(max_length=100, nullable=False)
    weight: float = SQLField(nullable=False)

    # Relationships
    slice: SmaliSlice = Relationship(back_populates="attributions")


class CertInReport(SQLModel, table=True):
    __tablename__ = "cert_in_reports"

    report_id: Optional[int] = SQLField(default=None, primary_key=True)
    apk_hash: str = SQLField(foreign_key="apks.apk_hash", max_length=64, unique=True, nullable=False, ondelete="CASCADE")
    mitre_attack_json: Dict[str, Any] = SQLField(default_factory=dict, sa_type=JSON, nullable=False)
    report_pdf_path: str = SQLField(max_length=512, nullable=False)
    compliance_status: str = SQLField(max_length=50, nullable=False)
    created_at: datetime = SQLField(default_factory=datetime.utcnow, nullable=False)

    # Relationships
    apk: APK = Relationship(back_populates="report")
