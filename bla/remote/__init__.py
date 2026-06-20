"""Remote workspace primitives for agentless log collection."""

from .ssh_workspace import RemoteWorkspace, SSHClient

__all__ = ["RemoteWorkspace", "SSHClient"]
