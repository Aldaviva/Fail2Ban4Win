#nullable enable

using Fail2Ban4Win.Config;
using Fail2Ban4Win.Data;
using Fail2Ban4Win.Facades;
using Fail2Ban4Win.Injection;
using Fail2Ban4Win.Plugins;
using Plugins;
using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using WindowsFirewallHelper;
using WindowsFirewallHelper.Addresses;
using WindowsFirewallHelper.FirewallRules;

namespace Fail2Ban4Win.Services;

public interface BanManager: IDisposable;

public sealed class BanManagerImpl: BanManager {

    private static readonly Logger LOGGER = LogManager.GetLogger(nameof(BanManagerImpl));

    private const FirewallProfiles ALL_PROFILES = FirewallProfiles.Domain | FirewallProfiles.Private | FirewallProfiles.Public;
    private const string           GROUP_NAME   = "Fail2Ban4Win";

    private static readonly IPNetwork2 LOOPBACK = IPNetwork2.Parse(IPAddress.Loopback, IPNetwork2.ToNetmask(8, AddressFamily.InterNetwork));

    private readonly EventLogListener                    eventLogListener;
    private readonly Configuration                       configuration;
    private readonly FirewallFacade                      firewall;
    private readonly IPluginManager<IFail2Ban4WinPlugin> pluginManager;
    private readonly IPAddress                           subnetMask;

    private readonly ConcurrentDictionary<IPNetwork2, SubnetFailureHistory> failures                = new();
    private readonly CancellationTokenSource                                cancellationTokenSource = new();
    private readonly ManualResetEventSlim                                   initialRuleDeletionDone = new(false);

    public BanManagerImpl(EventLogListener eventLogListener, Configuration configuration, FirewallFacade firewall, IPluginManager<IFail2Ban4WinPlugin> pluginManager) {
        this.eventLogListener = eventLogListener;
        this.configuration    = configuration;
        this.firewall         = firewall;
        this.pluginManager    = pluginManager;

        subnetMask = IPNetwork2.ToNetmask((byte) (32 - (this.configuration.banSubnetBits ?? 0)), AddressFamily.InterNetwork);

        eventLogListener.failure += onFailure;

        if (configuration.isDryRun) {
            LOGGER.Warn("Started in dry run mode. No changes will be made to Windows Firewall. If you're satisfied with the configuration and want to actually create firewall rules, set {config} " +
                "to false in {file}.", nameof(Configuration.isDryRun), ConfigurationModule.FILENAME);
        }

        Task.Run(init, cancellationTokenSource.Token);
    }

    private void init() {
        try {
            IEnumerable<FirewallWASRule> oldRules = firewall.Rules.Where(isBanRule()).ToList();
            if (oldRules.Any()) {
                if (configuration.unbanAllOnStartup) {
                    LOGGER.Info("Deleting {count} existing rules from Windows Firewall because Fail2Ban4Win restarted. To preserve them, set {config} to false in {file}.", oldRules.Count(),
                        nameof(Configuration.unbanAllOnStartup), ConfigurationModule.FILENAME);
                    foreach (FirewallWASRule oldRule in oldRules) {
                        if (!configuration.isDryRun) {
                            firewall.Rules.Remove(oldRule);
                        }
                    }
                } else {
                    DateTimeOffset now             = DateTimeOffset.Now;
                    int            scheduledUnbans = 0;
                    foreach (FirewallWASRule oldRule in oldRules) {
                        if (parseBan(oldRule) is {} ban) {
                            TimeSpan remainingBanDuration = ban.End - now;
                            if (remainingBanDuration > TimeSpan.Zero) {
                                scheduleUnban(ban.Subnet, remainingBanDuration);
                                scheduledUnbans++;
                                LOGGER.Debug("Resumed timer after Fail2Ban4Win restarted to unban {subnet} at the original time of {time:O} (in {duration:g})", ban.Subnet, ban.End,
                                    remainingBanDuration);
                            } else {
                                if (!configuration.isDryRun) {
                                    LOGGER.Info("Ban already expired on subnet {subnet} while Fail2Ban4Win wasn't running, removing firewall rule {name} now", ban.Start, oldRule.Name);
                                    firewall.Rules.Remove(oldRule);
                                }

                                foreach (IFail2Ban4WinPlugin plugin in pluginManager.Plugins) {
                                    plugin.OnBanLifted(ban);
                                }
                            }
                        } else if (!configuration.isDryRun) {
                            LOGGER.Warn("Failed to parse name or description of existing rule while repopulating timers after restart, deleting malformed rule. Name: {name}, description: \"{desc}\"",
                                oldRule.Name, oldRule.Description);
                            firewall.Rules.Remove(oldRule);
                        }
                    }
                    LOGGER.Info("Resumed {count:N0} timers to unban subnets after Fail2Ban4Win restarted", scheduledUnbans);
                }
            }

            initialRuleDeletionDone.Set();
        } catch (Exception e) when (e is not OutOfMemoryException) {
            LOGGER.Error(e, "Uncaught exception in {func}", nameof(init));
        }
    }

    private void onFailure(object sender, FailureParams failure) {
        foreach (IFail2Ban4WinPlugin plugin in pluginManager.Plugins) {
            plugin.OnAuthFailureDetected(failure);
        }

        IPNetwork2           subnet            = IPNetwork2.Parse(failure.Sender, subnetMask);
        SubnetFailureHistory failuresForSubnet = failures.GetOrAdd(subnet, _ => new ArrayListSubnetFailureHistory(configuration.maxAllowedFailures));
        BanParams?           ban               = null;

        lock (failuresForSubnet) {
            failuresForSubnet.add(DateTimeOffset.Now);

            if (shouldBan(subnet, failuresForSubnet)) {
                ban = this.ban(subnet, failuresForSubnet);
            }
        }

        if (ban is not null) {
            foreach (IFail2Ban4WinPlugin plugin in pluginManager.Plugins) {
                plugin.OnSubnetBanned(ban.Value);
            }
        }
    }

    // this runs inside a lock on the SubnetFailureHistory
    private bool shouldBan(IPNetwork2 subnet, SubnetFailureHistory clientFailureHistory) {
        if (subnet.IsIANAReserved() && configuration.neverBanReservedSubnets) {
            LOGGER.Debug("Not banning {subnet} because it is contained in an IANA-reserved block such as {reserved1}. To ban anyway, set {config} to false.", subnet, IPNetwork2.IANA_CBLK_RESERVED1,
                nameof(configuration.neverBanReservedSubnets));
            return false;
        }

        if (LOOPBACK.Contains(subnet)) {
            LOGGER.Debug("Not banning {subnet} because it is a loopback address", subnet);
            return false;
        }

        IPNetwork2? neverBanSubnet = configuration.neverBanSubnets?.FirstOrDefault(neverBan => neverBan.Overlap(subnet));
        if (neverBanSubnet is not null) {
            LOGGER.Debug("Not banning {subnet} because it overlaps the {neverBan} subnet in the \"{config}\" values in {file}", subnet, neverBanSubnet, nameof(configuration.neverBanSubnets),
                ConfigurationModule.FILENAME);
            return false;
        }

        int recentFailureCount = clientFailureHistory.countFailuresSinceAndPrune(DateTimeOffset.Now - configuration.failureWindow);
        if (recentFailureCount <= configuration.maxAllowedFailures) {
            LOGGER.Debug("Not banning {subnet} because it has only failed {count} times in the last {window}, which does not exceed the maximum {max} failures allowed", subnet, recentFailureCount,
                configuration.failureWindow, configuration.maxAllowedFailures);
            return false;
        }

        if (firewall.Rules.Any(isBanRule(subnet))) {
            LOGGER.Debug("Not banning {subnet} because it is already banned. This is likely caused by receiving many failed requests before our first firewall rule took effect.", subnet);
            return false;
        }

        return true;
    }

    // this runs inside a lock on the SubnetFailureHistory
    private BanParams ban(IPNetwork2 subnet, SubnetFailureHistory clientFailureHistory) {
        clientFailureHistory.banCount++;

        initialRuleDeletionDone.Wait(cancellationTokenSource.Token);

        DateTimeOffset now           = DateTimeOffset.Now;
        TimeSpan       unbanDuration = getUnbanDuration(clientFailureHistory.banCount);
        BanParams      ban           = new(subnet, now, unbanDuration, clientFailureHistory.banCount);
        FirewallWASRuleWin7 rule = new(generateRuleName(subnet), FirewallAction.Block, FirewallDirection.Inbound, ALL_PROFILES) {
            Description     = generateRuleDescription(ban),
            Grouping        = GROUP_NAME,
            RemoteAddresses = [new NetworkAddress(subnet.Network, subnet.Netmask)]
        };

        if (!configuration.isDryRun) {
            firewall.Rules.Add(rule);
        }

        scheduleUnban(subnet, unbanDuration);

        if (!configuration.isDryRun) {
            LOGGER.Info("Added Windows Firewall rule to block inbound traffic from {subnet}, which will be removed at {time:O} (in {duration:g})", subnet, now + unbanDuration, unbanDuration);
            clientFailureHistory.clearFailures();
        } else {
            LOGGER.Info("Would have added Windows Firewall rule to block inbound traffic from {subnet}, but dry run mode is enabled, so skipping adding rule. " +
                "To actually add firewall rules, set {config} to false in {file} and restart Fail2Ban4Win.", subnet, nameof(Configuration.isDryRun), ConfigurationModule.FILENAME);
        }

        return ban;
    }

    private void scheduleUnban(IPNetwork2 subnet, TimeSpan unbanDuration) => Task.DelayLong(unbanDuration, cancellationTokenSource.Token)
        .ContinueWith(_ => unban(subnet), cancellationTokenSource.Token, TaskContinuationOptions.NotOnCanceled)
        .ContinueWith(result => LOGGER.Error(result.Exception, "Exception unbanning subnet {subnet}", subnet), cancellationTokenSource.Token, TaskContinuationOptions.OnlyOnFaulted);

    /// <summary>For first offenses, this returns <c>banPeriod</c> (from <c>configuration.json</c>). For repeated offenses, the ban period is increased by <c>banRepeatedOffenseCoefficient</c> each time. The ban period stops increasing after <c>banRepeatedOffenseMax</c> offenses.</summary>
    /// <remarks>
    ///     <para>Example using <c>banPeriod</c> = 1 day, <c>banRepeatedOffenseCoefficient</c> = 1, and <c>banRepeatedOffenseMax</c> = 4:</para>
    ///     <list type="table"><listheader><term>Offense</term> <description>Ban duration</description></listheader> <item><term>1st</term> <description>1 day</description></item> <item><term>2nd</term> <description>2 days</description></item> <item><term>3rd</term> <description>3 days</description></item> <item><term>4th</term> <description>4 days</description></item> <item><term>5th</term> <description>4 days</description></item> <item><term>6th</term> <description>4 days</description></item></list></remarks>
    /// <param name="banCount">How many times the subnet in question has been banned, including this time. Starts at <c>1</c> for a new subnet that is being banned for the first time.</param>
    /// <returns>How long the offending subnet should be banned.</returns>
    public TimeSpan getUnbanDuration(int banCount) {
        banCount = Math.Max(1, banCount);
        return configuration.banPeriod + TimeSpan.FromMilliseconds(
            (Math.Min(banCount, configuration.banRepeatedOffenseMax ?? 4) - 1) *
            (configuration.banRepeatedOffenseCoefficient ?? 0.0) *
            configuration.banPeriod.TotalMilliseconds);
    }

    private void unban(IPNetwork2 subnet) {
        IEnumerable<FirewallWASRule> rulesToRemove = firewall.Rules.Where(isBanRule(subnet)).ToList(); //eagerly evaluate Where clause to prevent concurrent modification below
        IList<BanParams>             unbanned      = [];
        foreach (FirewallWASRule rule in rulesToRemove) {
            LOGGER.Info("Ban has expired for subnet {subnet}, removing firewall rule {name}", subnet, rule.Name);
            if (!configuration.isDryRun) {
                firewall.Rules.Remove(rule);
            }

            if (parseBan(rule) is {} ban) {
                unbanned.Add(ban);
            }
        }

        foreach (BanParams ban in unbanned) {
            foreach (IFail2Ban4WinPlugin plugin in pluginManager.Plugins) {
                plugin.OnBanLifted(ban);
            }
        }
    }

    private static Func<FirewallWASRule, bool> isBanRule(IPNetwork2? subnet = null) {
        string? ruleName = subnet is not null ? generateRuleName(subnet) : null;
        return rule => rule.Grouping == GROUP_NAME && (ruleName is null || ruleName == rule.Name);
    }

    private static BanParams? parseBan(FirewallWASRule firewallRule) =>
        parseRuleName(firewallRule.Name) is {} subnet
        && BAN_DESCRIPTION_PATTERN.Match(firewallRule.Description) is { Success: true } match
        && DateTimeOffset.TryParseExact(match.Groups["banned"].Value, "s", null, DateTimeStyles.AssumeLocal, out DateTimeOffset bannedTime)
        && DateTimeOffset.TryParseExact(match.Groups["unban"].Value, "s", null, DateTimeStyles.AssumeLocal, out DateTimeOffset unbanTime)
        && int.TryParse(match.Groups["offense"].Value, NumberStyles.AllowThousands, null, out int offense)
            ? new BanParams(subnet, bannedTime, unbanTime - bannedTime, offense) : null;

    private static string generateRuleName(IPNetwork2 subnet) => $"Banned {subnet}";

    private static readonly Regex BAN_NAME_PATTERN = new(@"^Banned (?<subnet>[\d\./]+?)$");

    private static IPNetwork2? parseRuleName(string name) =>
        BAN_NAME_PATTERN.Match(name) is { Success: true } match && IPNetwork2.TryParse(match.Groups["subnet"].Value, out IPNetwork2 subnet) ? subnet : null;

    private static string generateRuleDescription(BanParams ban) => $"Banned {ban.Start:s}. Will unban {ban.Start + ban.Duration:s}. Offense #{ban.OffenseCount:N0}.";

    private static readonly Regex BAN_DESCRIPTION_PATTERN = new(@"^Banned (?<banned>[\dT:-]+?)\. Will unban (?<unban>[\dT:-]+?)\. Offense #(?<offense>[\d, .']+?)\.$");

    public void Dispose() {
        eventLogListener.failure -= onFailure;
        cancellationTokenSource.Cancel();
    }

}