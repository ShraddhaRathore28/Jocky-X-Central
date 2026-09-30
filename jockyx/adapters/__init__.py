import platform
from .base import Adapter
from .replay import ReplayAdapter


def get_adapter(endpoint_id=None, os_name=None):
    """Pick the live adapter for the current OS (lazy imports keep both importable anywhere)."""
    os_name = os_name or platform.system()
    if os_name == "Windows":
        from .windows import WindowsAdapter; return WindowsAdapter(endpoint_id)
    if os_name == "Linux":
        from .ubuntu import UbuntuAdapter; return UbuntuAdapter(endpoint_id)
    raise RuntimeError(f"No live adapter for {os_name}; use ReplayAdapter")
