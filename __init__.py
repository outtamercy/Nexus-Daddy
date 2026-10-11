"""Nexus Daddy — a small, first-party Nexus client for MO2 plugins.

The public API deliberately stays import-light.  Qt and mobase are imported
only when MO2 asks for the actual plugin window.
"""

from __future__ import annotations


def createPlugin():
    from .plugin import NexusDaddyPlugin
    return NexusDaddyPlugin()

