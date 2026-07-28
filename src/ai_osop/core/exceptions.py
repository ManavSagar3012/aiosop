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


class MCPApprovalRequired(MCPException):
    """A tool declared ``requires_approval=True`` was invoked without a valid
    approval gate (fail-closed). The platform must not dispatch a high-impact
    MCP action (e.g. active exploit, RCE-bearing scan) without operator approval
    wired in — previously the flag was declared on the tool definition but
    ignored in the execute path, so the gate existed only on paper.
    """

    pass


class MCPScopeDenied(MCPException):
    """A tool declared ``scope_check=True`` was invoked with a target host the
    client-side execution gate found out of scope (fail-closed). Defense-in-depth
    on top of the server-side scope check: the request never leaves the platform
    process when the target is outside the engagement scope.
    """

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
