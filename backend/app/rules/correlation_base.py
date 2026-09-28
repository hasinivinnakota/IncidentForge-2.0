"""Correlation rule abstraction."""

from abc import ABC, abstractmethod
from collections.abc import Sequence

from ..models.correlation import CorrelatableAlert, CorrelationMatch


class CorrelationRule(ABC):
    """Contract for all correlation rule implementations.

    Inspects an incoming alert and historical alerts within a configured
    time window to detect multi-event security activity patterns.
    """

    @property
    @abstractmethod
    def rule_id(self) -> str: ...

    @property
    @abstractmethod
    def rule_name(self) -> str: ...

    @property
    @abstractmethod
    def correlation_type(self) -> str: ...

    @property
    @abstractmethod
    def description(self) -> str: ...

    @property
    @abstractmethod
    def window_seconds(self) -> int: ...

    @abstractmethod
    def evaluate(
        self, incoming: CorrelatableAlert, history: Sequence[CorrelatableAlert]
    ) -> CorrelationMatch | None:
        """Evaluate whether incoming alert and history pool form a correlation match."""
        ...
