"""Public build artifacts and errors for the experimental DSP SDK."""
import os
from dataclasses import dataclass
from pathlib import Path


class SdkError(Exception):
    """A build, input, or artifact did not meet the declared SDK contract."""


@dataclass(frozen=True)
class MemoryLayout:
    pm_start: int = 0
    pm_end: int = 0x3FFF
    dm_start: int = 0
    dm_end: int = 0x3FFF

    def validate(self) -> None:
        for space, start, end in (("PM", self.pm_start, self.pm_end), ("DM", self.dm_start, self.dm_end)):
            if not 0 <= start <= end <= 0x3FFF:
                raise SdkError(f"Invalid {space} word-address bounds: {start:#x}..{end:#x}")


@dataclass(frozen=True)
class MemorySegment:
    name: str
    space: str
    word_address: int
    word_bytes: int
    data: bytes

    @property
    def word_count(self) -> int:
        return len(self.data) // self.word_bytes


@dataclass(frozen=True)
class BuildResult:
    elf_path: Path
    manifest_path: Path
    segments: tuple[MemorySegment, ...]


@dataclass(frozen=True)
class Toolchain:
    root: Path

    def executable(self, name: str) -> Path:
        path = self.root.resolve() / "bin" / name
        if name not in ("as218x", "ld21") or not path.is_file() or not os.access(path, os.X_OK):
            raise SdkError(f"Missing executable SDK tool: {path}")
        return path
