"""
Plugin Loader & Manager Module
"""
import os
import importlib.util
from typing import List, Type
from .base import AnalyzerPlugin

class PluginManager:
    def __init__(self, plugin_dir: str = None):
        if not plugin_dir:
            plugin_dir = os.path.dirname(__file__)
        self.plugin_dir = plugin_dir
        self.plugins: List[Type[AnalyzerPlugin]] = []

    def discover_plugins(self) -> List[Type[AnalyzerPlugin]]:
        """Scans plugin directory for valid AnalyzerPlugin sub-classes."""
        self.plugins.clear()
        if not os.path.exists(self.plugin_dir):
            return self.plugins

        for fname in os.listdir(self.plugin_dir):
            if fname.endswith(".py") and not fname.startswith("__") and fname not in ("base.py", "manager.py"):
                fpath = os.path.join(self.plugin_dir, fname)
                mod_name = f"revlab.plugins.{fname[:-3]}"
                spec = importlib.util.spec_from_file_location(mod_name, fpath)
                if spec and spec.loader:
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    for item in dir(mod):
                        val = getattr(mod, item)
                        if isinstance(val, type) and issubclass(val, AnalyzerPlugin) and val is not AnalyzerPlugin:
                            self.plugins.append(val)
        return self.plugins
