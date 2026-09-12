"""Explicit, local defensive response actions; nothing runs on import."""

from .firewall import FirewallManager
from .process import terminate_process
from .quarantine import QuarantineManager

__all__ = ["FirewallManager", "QuarantineManager", "terminate_process"]
