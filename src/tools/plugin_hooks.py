"""Plugin discovery and execution helpers for the detection pipeline."""

from __future__ import annotations

import importlib.util
import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, Any, Callable, Iterable, List, MutableMapping, Optional, Sequence

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .run_all_detection import ArtefactPaths


LOGGER = logging.getLogger(__name__)

PluginCallable = Callable[["PluginContext"], None]


class PluginError(RuntimeError):
    """Base class for plugin loading/execution problems."""


class PluginValidationError(PluginError):
    """Raised when a plugin module does not expose the required interface."""


class PluginKeyRequestError(PluginError):
    """Raised when a plugin attempts to opt-in to key access."""

    def __init__(self, plugin_name: str) -> None:
        super().__init__(
            f"Plugin '{plugin_name}' declares requires_key=True which is not permitted."
        )
        self.plugin_name = plugin_name


class PluginExecutionError(PluginError):
    """Raised when a plugin crashes during execution."""

    def __init__(self, plugin_name: str, original: BaseException) -> None:
        super().__init__(f"Plugin '{plugin_name}' failed: {original!r}")
        self.plugin_name = plugin_name
        self.original = original


@dataclass(slots=True)
class PluginDescriptor:
    """Metadata for a discovered plugin module."""

    name: str
    requires_key: bool
    path: Path
    module_name: str
    handler: PluginCallable


@dataclass(slots=True)
class PluginDiscoveryResult:
    """Container for discovered plugins and unresolved allow-list entries."""

    plugins: List[PluginDescriptor]
    missing: List[str]


@dataclass(slots=True)
class PluginContext:
    """Execution context passed to each plugin."""

    artefacts: "ArtefactPaths"
    pipeline_report: MutableMapping[str, Any]
    mapping_report: MutableMapping[str, Any]
    metadata: MutableMapping[str, Any]
    session_key_provided: bool
    plugin_name: Optional[str] = None
    plugin_module: Optional[str] = None

    def for_plugin(self, descriptor: PluginDescriptor) -> "PluginContext":
        """Return a shallow copy of the context bound to *descriptor*."""

        return PluginContext(
            artefacts=self.artefacts,
            pipeline_report=self.pipeline_report,
            mapping_report=self.mapping_report,
            metadata=self.metadata,
            session_key_provided=self.session_key_provided,
            plugin_name=descriptor.name,
            plugin_module=descriptor.module_name,
        )


def _load_module_from_path(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"plugin_{path.stem}", path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise PluginValidationError(f"Unable to load plugin at {path}")
    module = importlib.util.module_from_spec(spec)
    # Ensure the module has a unique key in sys.modules to avoid duplicate execution
    sys.modules.setdefault(spec.name, module)
    spec.loader.exec_module(module)
    return module


def discover_plugins(
    plugins_dir: Path,
    allowlist: Sequence[str],
    *,
    logger: Optional[logging.Logger] = None,
) -> PluginDiscoveryResult:
    """Discover plugin modules under *plugins_dir* filtered by *allowlist*."""

    log = logger or LOGGER
    requested = {entry.lower() for entry in allowlist if entry}
    if not requested:
        return PluginDiscoveryResult(plugins=[], missing=[])

    if not plugins_dir.exists():
        log.warning("Plugin directory %s does not exist", plugins_dir)
        return PluginDiscoveryResult(plugins=[], missing=sorted(requested))

    discovered: List[PluginDescriptor] = []
    remaining = set(requested)

    for path in sorted(plugins_dir.glob("*.py")):
        if path.name == "__init__.py":
            continue
        module = _load_module_from_path(path)
        plugin_name = getattr(module, "PLUGIN_NAME", path.stem)
        plugin_name_lower = str(plugin_name).lower()
        module_name_lower = path.stem.lower()
        if plugin_name_lower not in requested and module_name_lower not in requested:
            continue
        requires_key = getattr(module, "requires_key", None)
        if not isinstance(requires_key, bool):
            raise PluginValidationError(
                f"Plugin '{plugin_name}' must define boolean 'requires_key'"
            )
        handler = getattr(module, "run_plugin", None)
        if handler is None or not callable(handler):
            raise PluginValidationError(
                f"Plugin '{plugin_name}' must define callable 'run_plugin(context)'"
            )
        descriptor = PluginDescriptor(
            name=str(plugin_name),
            requires_key=requires_key,
            path=path,
            module_name=module.__name__,
            handler=handler,
        )
        discovered.append(descriptor)
        remaining.discard(plugin_name_lower)
        remaining.discard(module_name_lower)
        log.debug("Discovered plugin %s from %s", descriptor.name, path)

    return PluginDiscoveryResult(plugins=discovered, missing=sorted(remaining))


def execute_plugins(
    plugins: Iterable[PluginDescriptor],
    context: PluginContext,
    *,
    logger: Optional[logging.Logger] = None,
) -> None:
    """Execute *plugins* with a shared *context* after vetting."""

    log = logger or LOGGER
    for descriptor in plugins:
        if descriptor.requires_key:
            raise PluginKeyRequestError(descriptor.name)
        plugin_context = context.for_plugin(descriptor)
        log.info("Running plugin %s", descriptor.name)
        try:
            descriptor.handler(plugin_context)
        except PluginKeyRequestError:
            raise
        except Exception as exc:  # pragma: no cover - error propagation
            raise PluginExecutionError(descriptor.name, exc) from exc


__all__ = [
    "PluginDescriptor",
    "PluginDiscoveryResult",
    "PluginContext",
    "PluginError",
    "PluginValidationError",
    "PluginExecutionError",
    "PluginKeyRequestError",
    "discover_plugins",
    "execute_plugins",
]
