from .approved_host_policy import (
    install_approved_host_fail_closed_gate as _install_approved_host_fail_closed_gate,
)

_install_approved_host_fail_closed_gate()
del _install_approved_host_fail_closed_gate

__version__ = "0.6.0"
