"""Abstract base class every access-control model implements."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..common.entities import AccessRequest, AccessResponse


class AccessControlModel(ABC):
    """Uniform interface for all six models.

    Subclasses configure their own policy state (lattices, ACLs, roles,
    rules, mission graphs ...) but expose only `decide()` to the
    evaluator so scenarios can iterate over them blindly.
    """

    name: str = "AbstractModel"

    @abstractmethod
    def decide(self, request: AccessRequest) -> AccessResponse:
        """Return an AccessResponse for a single request."""

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name}>"
