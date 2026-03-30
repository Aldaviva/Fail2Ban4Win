using Fail2Ban4Win.Data;

namespace Fail2Ban4Win.Plugins;

/// <summary>
/// A plugin for Fail2Ban4Win that allows users to define custom logic that should run when an auth failure is detected, or a subnet is banned or unbanned.
/// </summary>
public interface IFail2Ban4WinPlugin {

    /// <summary>
    /// <para>An IP address has tried and failed to authenticate with invalid credentials.</para>
    /// <para>If there were enough failures for the sender's subnet, this will be followed by a call to <see cref="OnSubnetBanned"/>.</para>
    /// </summary>
    /// <param name="failure">Details about the IP address that triggered this failure, as well as the log in which it was detected.</param>
    void OnAuthFailureDetected(FailureParams failure);

    /// <summary>
    /// A subnet has been banned by having a firewall rule created that blocks inbound traffic from this IP range.
    /// </summary>
    /// <param name="ban">Details about the subnet and timing of the ban.</param>
    void OnSubnetBanned(BanParams ban);

    /// <summary>
    /// After being banned for a period of time, the ban expired, the subnet was unbanned, and the firewall rule was deleted, allowing traffic from this IP range once again.
    /// </summary>
    /// <param name="ban">Details about the subnet and timing of the ban.</param>
    void OnBanLifted(BanParams ban);

}