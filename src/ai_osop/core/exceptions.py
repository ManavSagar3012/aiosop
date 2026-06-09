"""
AI-OSOP Custom Exceptions
Structured exception hierarchy for observability and graceful degradation.
"""


class OSOException(Exception):
    """Base exception for all AI-OSOP errors."""

    def __init__(self, message: str, details: dict = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class MCPException(OSOException):
    """MCP protocol or server error."""

    pass


class MCPConnectionError(MCPException):
    """Cannot connect to MCP server."""

    pass


class MCPTimeoutError(MCPException):
    """MCP server did not respond in time."""

    pass


class ScopeException(OSOException):
    """Target is out of scope."""

    pass


class OutOfScopeError(ScopeException):
    """Explicitly out of scope."""

    pass


class ScopeValidationError(ScopeException):
    """Scope validation failed due to malformed input."""

    pass


class AgentException(OSOException):
    """Agent execution error."""

    pass


class AgentTaskFailed(AgentException):
    """Agent failed to complete assigned task."""

    pass


class AgentHallucinationDetected(AgentException):
    """Agent output failed validation or consistency check."""

    pass


class SafetyException(OSOException):
    """Safety policy violation."""

    pass


class ApprovalDeniedError(SafetyException):
    """Operator denied approval for action."""

    pass


class SandboxException(OSOException):
    """Sandbox execution error."""

    pass


class SandboxEscapeDetected(SafetyException):
    """Potential sandbox escape attempt detected."""

    pass


class MemoryException(OSOException):
    """Memory layer error."""

    pass


class GraphQueryError(MemoryException):
    """Neo4j query execution failed."""

    pass


class WorkflowException(OSOException):
    """Workflow state machine error."""

    pass


class WorkflowTransitionError(WorkflowException):
    """Invalid state transition attempted."""

    pass
