from .approved_host_policy import (
    install_approved_host_authority_health_gate as _install_approved_host_authority_health_gate,
)

_install_approved_host_authority_health_gate()
del _install_approved_host_authority_health_gate

__version__ = "0.6.0"
