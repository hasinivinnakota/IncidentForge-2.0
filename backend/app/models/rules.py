"""Detection rule contract and match result model."""

from abc import ABC, abstractmethod

from pydantic import BaseModel, ConfigDict, Field

from .events import NormalizedEvent


class DetectionMatch(BaseModel):
    """Immutable record of a rule matching an event."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(min_length=1, max_length=128)
    rule_name: str = Field(min_length=1, max_length=256)
    event_id: str = Field(min_length=1, max_length=256)
    severity: int = Field(ge=0, le=15)
    description: str = Field(min_length=1, max_length=10000)
    mitre_techniques: list[str] = Field(default_factory=list)
    evidence: dict[str, object] = Field(default_factory=dict)


class DetectionRule(ABC):
    """Contract for all detection rule implementations.

    Future rule types (Sigma parser, Wazuh adapter, ML scorer)
    implement this ABC without inheriting fields they don't control.
    """

    @property
    @abstractmethod
    def rule_id(self) -> str: ...

    @property
    @abstractmethod
    def rule_name(self) -> str: ...

    @property
    @abstractmethod
    def description(self) -> str: ...

    @property
    @abstractmethod
    def severity(self) -> int: ...

    @property
    @abstractmethod
    def mitre_techniques(self) -> list[str]: ...

    @abstractmethod
    def evaluate(self, event: NormalizedEvent) -> DetectionMatch | None:
        """Return a DetectionMatch if the event triggers this rule, None otherwise."""
        ...
