"""Detector registry primitives."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional, Tuple

from ..models import DetectionAlert, LogEvent


DetectorCallable = Callable[[List[LogEvent]], List[DetectionAlert]]


@dataclass(frozen=True)
class DetectorSpec:
    """A detector registration entry.

    Empty ``profiles`` means the detector applies to every profile. Profile
    specific detectors, such as cn-hvv, can opt into only those profiles.
    """

    name: str
    run: DetectorCallable
    profiles: Tuple[str, ...] = ()
    description: str = ""

    def applies_to(self, profile: str) -> bool:
        return not self.profiles or profile in self.profiles


class DetectorRegistry:
    """Ordered detector registry used by the detection engine."""

    def __init__(self) -> None:
        self._detectors: List[DetectorSpec] = []

    def register(self, spec: DetectorSpec) -> None:
        self._detectors = [item for item in self._detectors if item.name != spec.name]
        self._detectors.append(spec)

    def list(self, profile: Optional[str] = None) -> List[DetectorSpec]:
        if profile is None:
            return list(self._detectors)
        return [item for item in self._detectors if item.applies_to(profile)]

    def names(self, profile: Optional[str] = None) -> List[str]:
        return [item.name for item in self.list(profile)]


def normalize_profiles(values: Iterable[str]) -> Tuple[str, ...]:
    return tuple(sorted({item.strip() for item in values if item.strip()}))
