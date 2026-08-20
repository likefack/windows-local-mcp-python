__version__ = "0.6.0"

# Install the Security Contract workspace commit boundary before any public submodule runs.
from .workspace_atomic import install as _install_workspace_atomic

_install_workspace_atomic()
del _install_workspace_atomic
