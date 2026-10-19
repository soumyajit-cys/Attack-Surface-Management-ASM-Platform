"""Pluggable scanner module registry with auto-discovery.

Scanner modules are plain Python files under the ``scanner_modules/`` package
that define a class decorated with ``@scanner_module(name, phase)``.  The
registry discovers them automatically on first access.

Usage::

    from app.scanning.registry import scanner_module, registry
    from app.scanning.context import ScanContext

    @scanner_module("port_scan", phase="port")
    async def run_port_scan(ctx: ScanContext) -> dict:
        ...

    # In the pipeline:
    for mod in registry.get_modules(phase="port"):
        result = await mod.run(ctx)
"""

from __future__ import annotations

import importlib
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Awaitable, Any

from app.scanning.context import ScanContext

logger = logging.getLogger(__name__)


class ScanPhase(str, Enum):
    """Ordered pipeline phases. Execution follows enum definition order."""
    DISCOVERY = "discovery"
    PORT = "port"
    SSL = "ssl"
    HEADER = "header"


@dataclass(frozen=True)
class ScannerEntry:
    """A registered scanner module."""
    name: str
    phase: ScanPhase
    run: Callable[[ScanContext], Awaitable[dict[str, Any]]]
    order: int = 0


class ScannerRegistry:
    """Central registry for all scanner modules.

    Modules register themselves via ``@scanner_module(name, phase)``.
    Discovery walks ``scanner_modules/`` once and caches the result.
    """

    #: Phases the scan pipeline executes through this registry. Discovery
    #: runs through services (resolve_domain etc.), not via registry modules.
    _PIPELINED_SCANNER_PHASES: tuple[ScanPhase, ...] = (
        ScanPhase.PORT,
        ScanPhase.SSL,
        ScanPhase.HEADER,
    )

    def __init__(self) -> None:
        self._entries: dict[str, ScannerEntry] = {}
        self._discovered = False
        # module name -> "ExcType: message" for every failed import
        self._failed_imports: dict[str, str] = {}

    @property
    def failed_imports(self) -> dict[str, str]:
        """Scanner modules that failed to import during discovery."""
        return dict(self._failed_imports)

    def unavailable_phases(self) -> list[str]:
        """Pipelined scanner phases that currently have NO modules.

        After discovery this lists every phase whose scanner module either
        failed to import or is missing entirely — the value surfaced in each
        scan summary and the scan detail API so a partially broken scanner
        package is never silent.
        """
        self._discover_once()
        registered = {entry.phase for entry in self._entries.values()}
        return [
            phase.value
            for phase in self._PIPELINED_SCANNER_PHASES
            if phase not in registered
        ]

    def warmup(self) -> list[str]:
        """Force discovery and log unavailable phases (called at startup).

        Returns the unavailable-phase list so callers can surface it too.
        """
        phases = self.unavailable_phases()
        if phases:
            logger.warning(
                "Scanner registry warm-up: phases unavailable "
                "(no registered scanner module): %s (failed imports: %s)",
                phases,
                self._failed_imports or "none",
            )
        else:
            logger.info("Scanner registry warm-up: all phases available")
        return phases

    def register(self, entry: ScannerEntry) -> None:
        if entry.name in self._entries:
            raise ValueError(f"Scanner module {entry.name!r} is already registered")
        self._entries[entry.name] = entry
        logger.debug("Registered scanner: %s (phase=%s)", entry.name, entry.phase.value)

    def get_modules(self, phase: ScanPhase | None = None) -> list[ScannerEntry]:
        """Return registered modules, optionally filtered by *phase*.

        Results are sorted by ``order`` within each phase.
        """
        self._discover_once()
        entries = list(self._entries.values())
        if phase is not None:
            entries = [e for e in entries if e.phase == phase]
        entries.sort(key=lambda e: (e.phase.value, e.order, e.name))
        return entries

    def get_by_name(self, name: str) -> ScannerEntry | None:
        self._discover_once()
        return self._entries.get(name)

    def list_all(self) -> list[ScannerEntry]:
        self._discover_once()
        return sorted(self._entries.values(), key=lambda e: (e.phase.value, e.order, e.name))

    def _discover_once(self) -> None:
        if self._discovered:
            return
        self._discovered = True
        _discover_scanner_modules(self)


def _discover_scanner_modules(reg: ScannerRegistry) -> None:
    """Import all modules in the ``scanner_modules`` package."""
    try:
        import scanner_modules as pkg
    except ImportError:
        logger.info("No scanner_modules package found; registry will be empty")
        return

    pkg_path = Path(pkg.__file__).parent  # type: ignore[union-attr]
    for py_file in sorted(pkg_path.glob("*.py")):
        if py_file.name.startswith("_"):
            continue
        module_name = f"scanner_modules.{py_file.stem}"
        try:
            importlib.import_module(module_name)
        except Exception as exc:
            reg._failed_imports[module_name] = f"{type(exc).__name__}: {exc}"
            logger.exception("Failed to import scanner module: %s", module_name)


def scanner_module(
    name: str,
    phase: ScanPhase | str,
    order: int = 0,
) -> Callable:
    """Decorator that registers a function as a scanner module.

    The decorated function must accept a ``ScanContext`` and return a dict.
    """
    if isinstance(phase, str):
        phase = ScanPhase(phase)

    def decorator(fn: Callable[[ScanContext], Awaitable[dict[str, Any]]]) -> Callable:
        entry = ScannerEntry(name=name, phase=phase, run=fn, order=order)
        # Registration happens at import time.  If the registry hasn't been
        # created yet (import order), we attach to the module-level instance.
        registry.register(entry)
        return fn

    return decorator


# Module-level singleton.
registry = ScannerRegistry()
