"""Detector registry primitives."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

from ..models import DetectionAlert, LogEvent

DetectorCallable = Callable[[List[LogEvent]], List[DetectionAlert]]
DetectorSelector = Callable[["DetectionEventIndex"], List[LogEvent]]


class DetectionEventIndex:
    """Single-pass event index used to preselect detector candidates."""

    def __init__(self, events: List[LogEvent]) -> None:
        self.events = events
        self.by_tag: Dict[str, List[LogEvent]] = defaultdict(list)
        self.by_event_id: Dict[str, List[LogEvent]] = defaultdict(list)
        self.by_category: Dict[str, List[LogEvent]] = defaultdict(list)
        for event in events:
            for tag in event.tags:
                self.by_tag[tag].append(event)
            if event.event_id:
                self.by_event_id[event.event_id].append(event)
            if event.category:
                self.by_category[event.category].append(event)

    def all(self) -> List[LogEvent]:
        return self.events

    def tags_any(self, *tags: str) -> List[LogEvent]:
        return _unique_events(event for tag in tags for event in self.by_tag.get(tag, ()))

    def event_ids(self, *event_ids: str) -> List[LogEvent]:
        return _unique_events(event for event_id in event_ids for event in self.by_event_id.get(event_id, ()))

    def categories(self, *categories: str) -> List[LogEvent]:
        return _unique_events(event for category in categories for event in self.by_category.get(category, ()))

    def union(self, *groups: Iterable[LogEvent]) -> List[LogEvent]:
        return _unique_events(event for group in groups for event in group)


def _unique_events(events: Iterable[LogEvent]) -> List[LogEvent]:
    seen: Set[str] = set()
    result: List[LogEvent] = []
    for event in events:
        if event.id in seen:
            continue
        seen.add(event.id)
        result.append(event)
    return result


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
    selector: Optional[DetectorSelector] = None

    def applies_to(self, profile: str) -> bool:
        return not self.profiles or profile in self.profiles

    def select_events(self, index: DetectionEventIndex) -> List[LogEvent]:
        return self.selector(index) if self.selector else index.all()


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
