from typing import Optional
from pydantic import BaseModel

from .alerts import Alert
from .cases import Case
from .correlation import Correlation
from .dataset import DatasetActivity, DatasetAsset
from .dataset_assessment import DatasetSecurityAssessment
from .incidents import Incident
from .response import ResponseAction
from .risk import RiskAssessment
from .threat_intel import ThreatIntelResult

class DatasetOverview(BaseModel):
    """Aggregate data contract for the Dataset Security Overview dashboard."""
    dataset_id: str
    asset: Optional[DatasetAsset] = None
    assessment: Optional[DatasetSecurityAssessment] = None
    activities: list[DatasetActivity] = []
    alerts: list[Alert] = []
    correlations: list[Correlation] = []
    incidents: list[Incident] = []
    risk_assessments: list[RiskAssessment] = []
    threat_intel: list[ThreatIntelResult] = []
    cases: list[Case] = []
    response_records: list[ResponseAction] = []
