"""Replaceable, passive local collectors. No persistence or enforcement."""

from .files import FileCollector
from .network import NetworkCollector
from .processes import ProcessCollector, build_process_tree
from .system import SystemInspector

__all__ = ["ProcessCollector", "NetworkCollector", "FileCollector", "SystemInspector", "build_process_tree"]
