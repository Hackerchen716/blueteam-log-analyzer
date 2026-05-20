"""Parser registry primitives.

The registry keeps log-source detection out of the CLI and gives future
collectors a stable way to parse either files or in-memory log chunks.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional, Tuple

from ..models import ParseResult


@dataclass(frozen=True)
class ParserContext:
    """Metadata available while selecting or running a parser."""

    source_name: str
    sample_text: str = ""
    file_path: Optional[str] = None
    content: Optional[str] = None
    file_size_bytes: int = 0

    @property
    def name_lower(self) -> str:
        return self.source_name.lower()


CanParse = Callable[[ParserContext], bool]
ParseCallable = Callable[[ParserContext], ParseResult]


@dataclass(frozen=True)
class ParserSpec:
    """A parser registration entry."""

    name: str
    aliases: Tuple[str, ...]
    can_parse: CanParse
    parse_file: Optional[ParseCallable] = None
    parse_content: Optional[ParseCallable] = None
    description: str = ""

    def matches(self, name: str) -> bool:
        target = name.lower().strip()
        return target == self.name or target in self.aliases


class ParserRegistry:
    """Ordered parser registry with explicit-parser override support."""

    def __init__(self) -> None:
        self._parsers: List[ParserSpec] = []

    def register(self, spec: ParserSpec) -> None:
        """Register or replace a parser by canonical name."""
        self._parsers = [item for item in self._parsers if item.name != spec.name]
        self._parsers.append(spec)

    def list(self) -> List[ParserSpec]:
        return list(self._parsers)

    def names(self) -> List[str]:
        return [item.name for item in self._parsers]

    def get(self, name: str) -> ParserSpec:
        for spec in self._parsers:
            if spec.matches(name):
                return spec
        choices = ", ".join(self.names())
        raise ValueError(f"未知日志类型: {name}（可选: {choices}）")

    def resolve(self, context: ParserContext, parser_name: Optional[str] = None) -> ParserSpec:
        if parser_name and parser_name != "auto":
            return self.get(parser_name)
        for spec in self._parsers:
            if spec.can_parse(context):
                return spec
        raise ValueError("没有可用解析器")

    def parse_file(self, context: ParserContext, parser_name: Optional[str] = None) -> ParseResult:
        spec = self.resolve(context, parser_name)
        if not spec.parse_file:
            raise ValueError(f"解析器 {spec.name} 不支持文件输入")
        return spec.parse_file(context)

    def parse_content(self, context: ParserContext, parser_name: Optional[str] = None) -> ParseResult:
        spec = self.resolve(context, parser_name)
        if not spec.parse_content:
            raise ValueError(f"解析器 {spec.name} 不支持内容输入")
        return spec.parse_content(context)


def normalize_aliases(values: Iterable[str]) -> Tuple[str, ...]:
    return tuple(sorted({item.lower().strip() for item in values if item.strip()}))
