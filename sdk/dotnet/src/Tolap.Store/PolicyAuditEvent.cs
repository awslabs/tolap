namespace Tolap.Store;

/// <summary>
/// Types of auditable policy events.
/// </summary>
public enum PolicyAuditEventType
{
    PolicyCreated,
    PolicyUpdated,
    PolicyDeleted,
    PolicyAssigned,
    PolicyRevoked
}

/// <summary>
/// Target of an audit event.
/// </summary>
public sealed record AuditTarget(string Type, string Identifier);

/// <summary>
/// Audit event raised when a policy mutation occurs.
/// </summary>
public sealed record PolicyAuditEvent(
    PolicyAuditEventType EventType,
    DateTimeOffset Timestamp,
    string Actor,
    AuditTarget Target,
    string Details);
