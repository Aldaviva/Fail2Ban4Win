using System.Net;

namespace Fail2Ban4Win.Data;

/// <summary>
/// An authentication failure by an address
/// </summary>
/// <param name="sender">The IP address that sent the failed request.</param>
/// <param name="selectorFriendlyName">The <c>friendlyName</c> of the event log selector.</param>
/// <param name="log">The name of the log that the event was logged in.</param>
/// <param name="eventId">The event's ID number.</param>
/// <param name="source">The source of the event.</param>
/// <param name="dateReceived">When the event was originally logged.</param>
public readonly struct FailureParams(IPAddress sender, string? selectorFriendlyName, string log, int eventId, string source, DateTimeOffset dateReceived) {

    /// <summary>
    /// The IP address that sent the failed request.
    /// </summary>
    public IPAddress Sender { get; } = sender;

    /// <summary>
    /// The <c>friendlyName</c> of the event log selector.
    /// </summary>
    public string? SelectorFriendlyName { get; } = selectorFriendlyName;

    /// <summary>
    /// The name of the log that the event was logged in.
    /// </summary>
    public string Log { get; } = log;

    /// <summary>
    /// The event's ID number.
    /// </summary>
    public int EventId { get; } = eventId;

    /// <summary>
    /// The source of the event.
    /// </summary>
    public string Source { get; } = source;

    /// <summary>
    /// >When the event was originally logged.
    /// </summary>
    public DateTimeOffset DateReceived { get; } = dateReceived;

    /// <inheritdoc cref="object.Equals(object)" />
    public bool Equals(FailureParams other) => Sender.Equals(other.Sender) && SelectorFriendlyName == other.SelectorFriendlyName && Log == other.Log && EventId == other.EventId &&
        Source == other.Source &&
        DateReceived.Equals(other.DateReceived);

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is FailureParams other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() {
        unchecked {
            int hashCode = Sender.GetHashCode();
            hashCode = (hashCode * 397) ^ (SelectorFriendlyName != null ? SelectorFriendlyName.GetHashCode() : 0);
            hashCode = (hashCode * 397) ^ Log.GetHashCode();
            hashCode = (hashCode * 397) ^ EventId;
            hashCode = (hashCode * 397) ^ Source.GetHashCode();
            hashCode = (hashCode * 397) ^ DateReceived.GetHashCode();
            return hashCode;
        }
    }

    /// <inheritdoc cref="object.Equals(object)" />
    public static bool operator ==(FailureParams left, FailureParams right) => left.Equals(right);

    /// <summary>
    /// Inverse of <see cref="op_Equality"/>
    /// </summary>
    public static bool operator !=(FailureParams left, FailureParams right) => !left.Equals(right);

}