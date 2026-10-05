"""Safe, identifiable transfer errors that MCP may disclose without a traceback."""

from mcp.server.mcpserver.exceptions import ToolError


class ArtifactTransferError(ValueError, ToolError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


class ArtifactTransferStateError(RuntimeError, ToolError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


class ArtifactTransferNotFoundError(FileNotFoundError, ToolError):
    """Retain filesystem compatibility while disclosing a safe MCP error."""

    def __init__(self) -> None:
        self.code = "TRANSFER_NOT_FOUND"
        super().__init__(f"{self.code}: transfer session was not found")
