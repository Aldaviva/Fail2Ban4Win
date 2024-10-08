﻿#nullable enable

using Fail2Ban4Win.Config;
using Fail2Ban4Win.Data;
using Fail2Ban4Win.Facades;
using Fail2Ban4Win.Injection;
using NLog;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using WindowsFirewallHelper;
using WindowsFirewallHelper.Addresses;
using WindowsFirewallHelper.FirewallRules;

namespace Fail2Ban4Win.Services;

public interface BanManager: IDisposable;

public class BanManagerImpl: BanManager {

    private static readonly Logger LOGGER = LogManager.GetLogger(nameof(BanManagerImpl));

    private const FirewallProfiles ALL_PROFILES = FirewallProfiles.Domain | FirewallProfiles.Private | FirewallProfiles.Public;
    private const string           GROUP_NAME   = "Fail2Ban4Win";

    private static readonly IPNetwork2 LOOPBACK = IPNetwork2.Parse(IPAddress.Loopback, IPNetwork2.ToNetmask(8, AddressFamily.InterNetwork));

    private readonly EventLogListener eventLogListener;
    private readonly Configuration    configuration;
    private readonly FirewallFacade   firewall;
    private readonly IPAddress        subnetMask;

    private readonly ConcurrentDictionary<IPNetwork2, SubnetFailureHistory> failures                = new();
    private readonly CancellationTokenSource                                cancellationTokenSource = new();
    private readonly ManualResetEventSlim                                   initialRuleDeletionDone = new(false);

    public BanManagerImpl(EventLogListener eventLogListener, Configuration configuration, FirewallFacade firewall) {
        this.eventLogListener = eventLogListener;
        this.configuration    = configuration;
        this.firewall         = firewall;

        subnetMask = IPNetwork2.ToNetmask((byte) (32 - (this.configuration.banSubnetBits ?? 0)), AddressFamily.InterNetwork);

        eventLogListener.failure += onFailure;

        if (configuration.isDryRun) {
            LOGGER.Info("Started in dry run mode. No changes will be made to Windows Firewall.");
        }

        Task.Run(() => {
            IEnumerable<FirewallWASRule> oldRules = firewall.Rules.Where(isBanRule()).ToList();
            if (oldRules.Any()) {
                LOGGER.Info("Deleting {0} existing {1} rules from Windows Firewall because they may be stale", oldRules.Count(), GROUP_NAME);
                foreach (FirewallWASRule oldRule in oldRules) {
                    if (!configuration.isDryRun) {
                        firewall.Rules.Remove(oldRule);
                    }
                }
            }

            initialRuleDeletionDone.Set();
        }, cancellationTokenSource.Token);
    }

    private void onFailure(object sender, IPAddress ipAddress) {
        IPNetwork2 subnet = IPNetwork2.Parse(ipAddress, subnetMask);

        SubnetFailureHistory failuresForSubnet = failures.GetOrAdd(subnet, _ => new ArrayListSubnetFailureHistory(configuration.maxAllowedFailures));
        lock (failuresForSubnet) {
            failuresForSubnet.add(DateTimeOffset.Now);

            if (shouldBan(subnet, failuresForSubnet)) {
                ban(subnet, failuresForSubnet);
            }
        }
    }

    // this runs inside a lock on the SubnetFailureHistory
    private bool shouldBan(IPNetwork2 subnet, SubnetFailureHistory clientFailureHistory) {
        if (subnet.IsIANAReserved() && configuration.neverBanReservedSubnets) {
            LOGGER.Debug("Not banning {0} because it is contained in an IANA-reserved block such as {1}. To ban anyway, set \"{2}\" to false.", subnet, IPNetwork2.IANA_CBLK_RESERVED1,
                nameof(configuration.neverBanReservedSubnets));
            return false;
        }

        if (LOOPBACK.Contains(subnet)) {
            LOGGER.Debug("Not banning {0} because it is a loopback address", subnet);
            return false;
        }

        IPNetwork2? neverBanSubnet = configuration.neverBanSubnets?.FirstOrDefault(neverBan => neverBan.Overlap(subnet));
        if (neverBanSubnet is not null) {
            LOGGER.Debug("Not banning {0} because it overlaps the {2} subnet in the \"{3}\" values in {1}", subnet, ConfigurationModule.CONFIGURATION_FILENAME, neverBanSubnet,
                nameof(configuration.neverBanSubnets));
            return false;
        }

        int recentFailureCount = clientFailureHistory.countFailuresSinceAndPrune(DateTimeOffset.Now - configuration.failureWindow);
        if (recentFailureCount <= configuration.maxAllowedFailures) {
            LOGGER.Debug("Not banning {0} because it has only failed {1} times in the last {2}, which does not exceed the maximum {3} failures allowed", subnet, recentFailureCount,
                configuration.failureWindow, configuration.maxAllowedFailures);
            return false;
        }

        if (firewall.Rules.Any(isBanRule(subnet))) {
            LOGGER.Debug("Not banning {0} because it is already banned. This is likely caused by receiving many failed requests before our first firewall rule took effect.", subnet);
            return false;
        }

        return true;
    }

    // this runs inside a lock on the SubnetFailureHistory
    private void ban(IPNetwork2 subnet, SubnetFailureHistory clientFailureHistory) {
        clientFailureHistory.banCount++;

        initialRuleDeletionDone.Wait(cancellationTokenSource.Token);

        DateTime now           = DateTime.Now;
        TimeSpan unbanDuration = getUnbanDuration(clientFailureHistory.banCount);

        FirewallWASRuleWin7 rule = new(getRuleName(subnet), FirewallAction.Block, FirewallDirection.Inbound, ALL_PROFILES) {
            Description     = $"Banned {now:s}. Will unban {now + unbanDuration:s}. Offense #{clientFailureHistory.banCount:N0}.",
            Grouping        = GROUP_NAME,
            RemoteAddresses = [new NetworkAddress(subnet.Network, subnet.Netmask)]
        };

        if (!configuration.isDryRun) {
            firewall.Rules.Add(rule);
        }

        LongDelay(unbanDuration, cancellationTokenSource.Token)
            .ContinueWith(_ => unban(subnet), cancellationTokenSource.Token, TaskContinuationOptions.NotOnCanceled, TaskScheduler.Current)
            .ContinueWith(result => LOGGER.Error(result.Exception, "Exception unbanning subnet {0}", subnet), cancellationTokenSource.Token, TaskContinuationOptions.OnlyOnFaulted,
                TaskScheduler.Current);

        LOGGER.Info("Added Windows Firewall rule to block inbound traffic from {0}, which will be removed at {1:O} (in {2:g})", subnet, now + unbanDuration, unbanDuration);

        if (!configuration.isDryRun) {
            clientFailureHistory.clearFailures();
        }
    }

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
        foreach (FirewallWASRule rule in rulesToRemove) {
            LOGGER.Info("Ban has expired on subnet {0}, removing firewall rule {1}", subnet, rule.Name);
            if (!configuration.isDryRun) {
                firewall.Rules.Remove(rule);
            }
        }
    }

    private static Func<FirewallWASRule, bool> isBanRule(IPNetwork2? subnet = null) {
        string? ruleName = subnet is not null ? getRuleName(subnet) : null;
        return rule => rule.Grouping == GROUP_NAME && (ruleName is null || ruleName == rule.Name);
    }

    private static string getRuleName(IPNetwork2 ipAddress) => $"Banned {ipAddress}";

    private static Task LongDelay(TimeSpan duration, CancellationToken cancellationToken = default) {
        /*
         * max duration of Task.Delay before .NET 6
         * https://learn.microsoft.com/en-us/dotnet/api/system.threading.tasks.task.delay?view=netframework-4.8#system-threading-tasks-task-delay(system-timespan-system-threading-cancellationtoken)
         */
        TimeSpan maxShortDelay = TimeSpan.FromMilliseconds(int.MaxValue);
        Task     result        = Task.CompletedTask;

        for (TimeSpan remaining = duration; remaining > TimeSpan.Zero; remaining = remaining.Subtract(maxShortDelay)) {
            TimeSpan shortDelay = remaining > maxShortDelay ? maxShortDelay : remaining;
            result = result.ContinueWith(_ => Task.Delay(shortDelay, cancellationToken), cancellationToken,
                TaskContinuationOptions.LongRunning | TaskContinuationOptions.NotOnCanceled, TaskScheduler.Current).Unwrap();
        }

        return result;
    }

    public void Dispose() {
        eventLogListener.failure -= onFailure;
        cancellationTokenSource.Cancel();
    }

}