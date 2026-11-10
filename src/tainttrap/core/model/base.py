"""Assessment providers: the model behind the decision core (FR-016)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Protocol

from tainttrap.core.types import Assessment, Dossier


class ModelUnavailable(RuntimeError):
    """The provider cannot answer (not installed, integrity failure, crashed)."""


class AssessmentProvider(Protocol):
    model_id: str

    async def assess(self, dossier: Dossier) -> Assessment: ...


class StubProvider:
    """Returns a fixed Assessment, or the result of a callable. Used by tests."""

    model_id = "stub"

    def __init__(
        self,
        result: Assessment | Callable[[Dossier], Assessment | Awaitable[Assessment]],
    ) -> None:
        self._result = result
        self.calls: list[Dossier] = []

    async def assess(self, dossier: Dossier) -> Assessment:
        self.calls.append(dossier)
        if isinstance(self._result, Assessment):
            return self._result
        out = self._result(dossier)
        if isinstance(out, Assessment):
            return out
        return await out


class DisabledProvider:
    """`model.enabled: false` or no model installed: always unavailable."""

    model_id = "disabled"

    async def assess(self, dossier: Dossier) -> Assessment:
        raise ModelUnavailable("model disabled")
