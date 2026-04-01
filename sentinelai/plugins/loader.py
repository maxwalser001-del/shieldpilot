"""Dynamic plugin loader.

Discovers and loads plugins from the configured plugins directory.
Each plugin is a .py file containing a class that extends SentinelPlugin.
"""

from __future__ import annotations

import importlib.util
import inspect
import logging
from pathlib import Path
from typing import List, Optional

from sentinelai.core.config import SentinelConfig
from sentinelai.core.exceptions import PluginError
from sentinelai.plugins.interface import SentinelPlugin

logger = logging.getLogger(__name__)


class PluginLoader:
    """Discovers, loads, and manages ShieldPilot plugins.

    Plugins are Python files in the plugins directory that contain
    classes extending SentinelPlugin. Each file can contain one plugin.
    """

    def __init__(self, config: SentinelConfig):
        self.config = config
        self.plugins: List[SentinelPlugin] = []

    def load_plugins(self, directory: Optional[str] = None) -> List[SentinelPlugin]:
        """Discover and load all plugins from the given directory.

        Args:
            directory: Path to plugins directory. Defaults to config value.

        Returns:
            List of loaded plugin instances.
        """
        plugin_dir = Path(directory or self.config.plugins.directory)

        if not plugin_dir.exists():
            logger.debug(f"Plugin directory does not exist: {plugin_dir}")
            return []

        if not plugin_dir.is_dir():
            logger.warning(f"Plugin path is not a directory: {plugin_dir}")
            return []

        loaded = []

        for py_file in sorted(plugin_dir.glob("*.py")):
            if py_file.name.startswith("_"):
                continue

            try:
                plugin = self._load_plugin_file(py_file)
                if plugin is not None:
                    # Initialize the plugin
                    plugin.on_load(self.config)
                    loaded.append(plugin)
                    logger.info(f"Loaded plugin: {plugin.name} v{plugin.version}")
            except Exception as e:
                logger.warning(f"Failed to load plugin {py_file.name}: {e}")

        self.plugins = loaded
        return loaded

    def _load_plugin_file(self, path: Path) -> Optional[SentinelPlugin]:
        """Load a single plugin from a Python file.

        Finds the first class in the file that extends SentinelPlugin
        and instantiates it.
        """
        module_name = f"sentinel_plugin_{path.stem}"

        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            return None

        module = importlib.util.module_from_spec(spec)

        try:
            spec.loader.exec_module(module)
        except Exception as e:
            raise PluginError(path.stem, f"Module execution failed: {e}")

        # Find SentinelPlugin subclasses in the module
        for _name, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, SentinelPlugin)
                and obj is not SentinelPlugin
                and obj.__module__ == module_name
            ):
                try:
                    return obj()
                except Exception as e:
                    raise PluginError(path.stem, f"Instantiation failed: {e}")

        logger.debug(f"No SentinelPlugin subclass found in {path.name}")
        return None

    def execute_hook(self, hook_name: str, *args, **kwargs):
        """Execute a hook on all loaded plugins, catching errors.

        Returns the first non-None result from any plugin, or None.
        """
        result = None
        for plugin in self.plugins:
            hook = getattr(plugin, hook_name, None)
            if hook is None:
                continue
            try:
                r = hook(*args, **kwargs)
                if r is not None and result is None:
                    result = r
            except Exception as e:
                logger.warning(
                    f"Plugin {plugin.name} hook {hook_name} failed: {e}"
                )
        return result
