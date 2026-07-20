"""
RevLab Analyzer Plugin Interface Base Class
"""
from abc import ABC, abstractmethod
from typing import Dict, Any
from ..parsers.common import BinaryObject

class AnalyzerPlugin(ABC):
    name: str = "base_plugin"
    description: str = "Base plugin description"
    version: str = "1.0.0"

    @abstractmethod
    def analyze(self, binary: BinaryObject) -> Dict[str, Any]:
        """Performs custom analysis pass on BinaryObject."""
        pass

    @abstractmethod
    def render(self, result: Dict[str, Any]):
        """Renders rich terminal output for analysis results."""
        pass
