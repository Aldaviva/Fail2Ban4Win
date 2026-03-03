using System.Net;

namespace Fail2Ban4Win.Data;

/// <summary>
/// A ban on a subnet
/// </summary>
/// <param name="subnet">The IP range whose traffic is rejected.</param>
/// <param name="start">When the ban went into effect.</param>
/// <param name="duration">How long the ban lasts.</param>
/// <param name="offenseCount">How many times this subnet has been banned recently, including this one (starts at 1).</param>
public readonly struct BanParams(IPNetwork2 subnet, DateTime start, TimeSpan duration, int offenseCount) {

    /// <summary>
    /// The IP range whose traffic is rejected.
    /// </summary>
    public IPNetwork2 Subnet { get; } = subnet;

    /// <summary>
    /// When the ban went into effect.
    /// </summary>
    public DateTime Start { get; } = start;

    /// <summary>
    /// How long the ban lasts.
    /// </summary>
    public TimeSpan Duration { get; } = duration;

    /// <summary>
    /// How many times this subnet has been banned recently, including this one (starts at 1).
    /// </summary>
    public int OffenseCount { get; } = offenseCount;

    /// <summary>
    /// When the ban ends and the firewall rule is removed.
    /// </summary>
    public DateTime End => Start + Duration;

    /// <inheritdoc cref="object.Equals(object)" />
    public bool Equals(BanParams other) => Subnet.Equals(other.Subnet) && Start.Equals(other.Start) && Duration.Equals(other.Duration) && OffenseCount == other.OffenseCount;

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is BanParams other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() {
        unchecked {
            int hashCode = Subnet.GetHashCode();
            hashCode = (hashCode * 397) ^ Start.GetHashCode();
            hashCode = (hashCode * 397) ^ Duration.GetHashCode();
            hashCode = (hashCode * 397) ^ OffenseCount;
            return hashCode;
        }
    }

    /// <inheritdoc cref="object.Equals(object)" />
    public static bool operator ==(BanParams left, BanParams right) => left.Equals(right);

    /// <summary>
    /// Inverse of <see cref="op_Equality"/>
    /// </summary>
    public static bool operator !=(BanParams left, BanParams right) => !left.Equals(right);

}