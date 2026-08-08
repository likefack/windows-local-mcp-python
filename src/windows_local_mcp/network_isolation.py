from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class NetworkPolicy:
    name: str
    internet: str
    lan: str
    loopback: str
    enforcement: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "internet": self.internet,
            "lan": self.lan,
            "loopback": self.loopback,
            "enforcement": self.enforcement,
        }


def safe_network_policy(program_key: str) -> NetworkPolicy:
    if program_key == "adb":
        return NetworkPolicy(
            "adb-loopback-only", "deny", "deny", "allow", "command-and-environment-boundary"
        )
    return NetworkPolicy("offline", "deny", "deny", "deny", "command-and-environment-boundary")


def apply_safe_network_environment(environment: dict[str, str], program_key: str) -> None:
    """Constrain supported tool transports; unknown network-needing work stays approval-only.

    This complements the closed safe grammar. It is deliberately explicit in audit as a
    command/environment boundary rather than claiming an OS/WFP sandbox.
    """
    blackhole = "http://127.0.0.1:1"
    environment.update(
        {
            "HTTP_PROXY": blackhole,
            "HTTPS_PROXY": blackhole,
            "ALL_PROXY": blackhole,
            "NO_PROXY": "127.0.0.1,localhost,::1" if program_key == "adb" else "",
            "PUB_HOSTED_URL": blackhole,
        }
    )
    if program_key == "adb":
        environment["ADB_SERVER_SOCKET"] = "tcp:127.0.0.1:5037"
    if program_key == "git":
        environment["GIT_ALLOW_PROTOCOL"] = "file"
