"""Source-agnostic telemetry adapter contract."""

from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from typing import Any


class TelemetryAdapter(ABC):
    """Interface implemented by future Wazuh, file, and fixture adapters."""

    @abstractmethod
    def get_events(self) -> Sequence[Mapping[str, Any]]:
        """Return source events without imposing a source-specific schema."""
        raise NotImplementedError