"""Detection engine service evaluating events against registered detection rules."""

from collections.abc import Sequence

from ..models.events import NormalizedEvent
from ..models.rules import DetectionMatch, DetectionRule


class DetectionEngine:
    """Stateless rule evaluator. Holds a registry of rules, evaluates an event against all."""

    def __init__(self, rules: Sequence[DetectionRule]):
        self._rules = list(rules)

    @property
    def rules(self) -> list[DetectionRule]:
        return list(self._rules)

    def evaluate(self, event: NormalizedEvent) -> list[DetectionMatch]:
        matches: list[DetectionMatch] = []
        for rule in self._rules:
            match = rule.evaluate(event)
            if match is not None:
                matches.append(match)
        return matches
