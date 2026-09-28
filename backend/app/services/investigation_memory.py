"""Advisory Hindsight memory boundary for investigations."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
import json
import logging
import time
from typing import TYPE_CHECKING, Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from pydantic import BaseModel, ConfigDict, Field

from ..config import Settings, get_settings

if TYPE_CHECKING:
    from .llm_provider import LLMContext

logger = logging.getLogger(__name__)


class MemoryItem(BaseModel):
    """A bounded, provenance-carrying historical memory."""

    model_config = ConfigDict(extra="ignore")

    memory_id: str = Field(min_length=1, max_length=256)
    content: str = Field(min_length=1, max_length=2000)
    source_incident_id: str | None = Field(default=None, max_length=256)
    label: str | None = Field(default=None, max_length=64)
    reliability: float = Field(default=0.0, ge=0.0, le=1.0)


class AnalystFeedback(BaseModel):
    """Feedback contract reserved for Phase 2 persistence and analyst APIs."""

    model_config = ConfigDict(extra="forbid")

    incident_id: str
    investigation_id: str
    label: str
    reason: str = Field(min_length=1, max_length=2000)
    corrected_finding: str | None = Field(default=None, max_length=2000)


class InvestigationMemory(ABC):
    """Provider boundary for historical investigation context."""

    @abstractmethod
    def retrieve(self, context: "LLMContext") -> list[MemoryItem]:
        raise NotImplementedError

    @abstractmethod
    def record_feedback(self, feedback: AnalystFeedback) -> None:
        raise NotImplementedError


class NoOpInvestigationMemory(InvestigationMemory):
    """Disabled provider used by default and in tests."""

    def retrieve(self, context: "LLMContext") -> list[MemoryItem]:
        return []

    def record_feedback(self, feedback: AnalystFeedback) -> None:
        return None


@dataclass
class _CircuitState:
    failures: int = 0
    opened_at: float | None = None


class HindsightInvestigationMemory(InvestigationMemory):
    """Small fail-open HTTP adapter around Hindsight's recall endpoint."""

    def __init__(self, settings: Settings):
        self._endpoint = settings.hindsight_endpoint
        self._timeout = settings.hindsight_timeout_seconds
        self._max_memories = max(0, settings.hindsight_max_memories)
        self._failure_threshold = max(1, settings.hindsight_failure_threshold)
        self._cooldown = max(0.0, settings.hindsight_cooldown_seconds)
        self._circuit = _CircuitState()

    def retrieve(self, context: "LLMContext") -> list[MemoryItem]:
        if self._circuit_open():
            return []
        try:
            payload = self._request(
                "/v1/memories/recall",
                {"query": self._query(context), "limit": self._max_memories},
            )
            raw_memories = payload.get("memories", payload) if isinstance(payload, dict) else payload
            memories = [MemoryItem.model_validate(item) for item in raw_memories or []]
            self._record_success()
            return memories[: self._max_memories]
        except Exception as exc:
            self._record_failure(exc)
            return []

    def record_feedback(self, feedback: AnalystFeedback) -> None:
        if self._circuit_open():
            return
        try:
            self._request("/v1/memories/feedback", feedback.model_dump(mode="json"))
            self._record_success()
        except Exception as exc:
            self._record_failure(exc)

    @staticmethod
    def _query(context: "LLMContext") -> dict[str, Any]:
        return {
            "incident_id": context.incident_id,
            "title": context.incident_title,
            "entity_id": context.entity_id,
            "mitre_techniques": context.mitre_techniques[:10],
            "risk_level": context.risk_level,
        }

    def _request(self, path: str, payload: dict[str, Any]) -> Any:
        request = Request(
            f"{self._endpoint}{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        last_error: Exception | None = None
        for attempt in range(2):
            try:
                with urlopen(request, timeout=self._timeout) as response:  # noqa: S310
                    return json.loads(response.read().decode("utf-8"))
            except (OSError, URLError, ValueError) as exc:
                last_error = exc
                if attempt == 0:
                    continue
        raise RuntimeError(f"Hindsight request failed: {last_error}")

    def _circuit_open(self) -> bool:
        if self._circuit.opened_at is None:
            return False
        if time.monotonic() - self._circuit.opened_at >= self._cooldown:
            self._circuit = _CircuitState()
            return False
        return True

    def _record_success(self) -> None:
        self._circuit = _CircuitState()

    def _record_failure(self, exc: Exception) -> None:
        self._circuit.failures += 1
        if self._circuit.failures >= self._failure_threshold:
            self._circuit.opened_at = time.monotonic()
        logger.warning("Hindsight memory operation failed; continuing without memory: %s", exc)


def build_investigation_memory(settings: Settings | None = None) -> InvestigationMemory:
    settings = settings or get_settings()
    if not settings.hindsight_enabled:
        return NoOpInvestigationMemory()
    return HindsightInvestigationMemory(settings)