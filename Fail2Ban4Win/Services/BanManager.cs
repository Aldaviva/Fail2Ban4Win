using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using WindowsFirewallHelper;
using WindowsFirewallHelper.Addresses;
using WindowsFirewallHelper.FirewallRules;
using Fail2Ban4Win.Config;
using Fail2Ban4Win.Data;
using Fail2Ban4Win.Facades;
using Fail2Ban4Win.Injection;
using FluentScheduler;
using NLog;

#nullable enable

namespace Fail2Ban4Win.Services {

    public interface BanManager: IDisposable { }

    public class BanManagerImpl: BanManager {

        private static readonly Logger LOGGER = LogManager.GetLogger(nameof(BanManagerImpl));

        private const FirewallProfiles ALL_PROFILES = FirewallProfiles.Domain | FirewallProfiles.Private | FirewallProfiles.Public;
        private const string           GROUP_NAME   = "Fail2Ban4Win";

        private static readonly IPNetwork LOOPBACK = IPNetwork.Parse(IPAddress.Loopback, IPNetwork.ToNetmask(8, AddressFamily.InterNetwork));

        private readonly EventLogListener eventLogListener;
        private readonly Configuration    configuration;
        private readonly FirewallFacade   firewall;

        private readonly ConcurrentDictionary<IPNetwork, SubnetFailureHistory> failures = new();

        public BanManagerImpl(EventLogListener eventLogListener, Configuration configuration, FirewallFacade firewall) {
            this.eventLogListener = eventLogListener;
            this.configuration    = configuration;
            this.firewall         = firewall;

            JobManager.Initialize(new Registry());

            IEnumerable<FirewallWASRule> oldRules = firewall.Rules.Where(isBanRule()).ToList();
            if (oldRules.Any()) {
                LOGGER.Info("Deleting {0} existing {1} rules from Windows Firewall because they may be stale.", oldRules.Count(), GROUP_NAME);
                foreach (FirewallWASRule oldRule in oldRules) {
                    if (!configuration.isDryRun) {
                        firewall.Rules.Remove(oldRule);
                    }
                }
            }

            eventLogListener.failure += onFailure;

            if (configuration.isDryRun) {
                LOGGER.Info("Started in dry run mode. No changes will be made to Windows Firewall.");
            }
        }

        private void onFailure(object sender, IPAddress ipAddress) {
            IPNetwork subnet = IPNetwork.Parse(ipAddress, IPNetwork.ToNetmask((byte) (32 - (configuration.banSubnetBits ?? 0)), AddressFamily.InterNetwork));

            SubnetFailureHistory failuresForSubnet = failures.GetOrAdd(subnet, _ => new ArrayListSubnetFailureHistory(configuration.maxAllowedFailures));
            lock (failuresForSubnet) {
                failuresForSubnet.add(DateTimeOffset.Now);

                if (shouldBan(subnet, failuresForSubnet)) {
                    ban(subnet, failuresForSubnet);
                }
            }
        }

        // this runs inside a lock on the SubnetFailureHistory
        private bool shouldBan(IPNetwork subnet, SubnetFailureHistory clientFailureHistory) {
            if (subnet.IsIANAReserved()) {
                LOGGER.Debug("Not banning {0} because it is contained in an IANA-reserved block such as {1}.", subnet, IPNetwork.IANA_CBLK_RESERVED1);
                return false;
            }

            if (LOOPBACK.Contains(subnet)) {
                LOGGER.Debug("Not banning {0} because it is a loopback address.", subnet);
                return false;
            }

            IPNetwork? neverBanSubnet = configuration.neverBanSubnets?.FirstOrDefault(neverBan => neverBan.Overlap(subnet));
            if (neverBanSubnet is not null) {
                LOGGER.Debug("Not banning {0} because it overlaps the {2} subnet in the \"neverBanSubnets\" values in {1}.", subnet, ConfigurationModule.CONFIGURATION_FILENAME, neverBanSubnet);
                return false;
            }

            int recentFailureCount = clientFailureHistory.countFailuresSinceAndPrune(DateTimeOffset.Now - configuration.failureWindow);
            if (recentFailureCount <= configuration.maxAllowedFailures) {
                LOGGER.Debug("Not banning {0} because it has only failed {1} times in the last {2}, which does not exceed the maximum {3} failures allowed.", subnet, recentFailureCount,
                    configuration.failureWindow, configuration.maxAllowedFailures);
                return false;
            }

            return true;
        }

        // this runs inside a lock on the SubnetFailureHistory
        private void ban(IPNetwork subnet, SubnetFailureHistory clientFailureHistory) {
            clientFailureHistory.banCount++;

            DateTime now       = DateTime.Now;
            DateTime unbanTime = now + TimeSpan.FromMilliseconds(Math.Min(clientFailureHistory.banCount, 4) * configuration.banPeriod.TotalMilliseconds);

            var rule = new FirewallWASRuleWin7(getRuleName(subnet), FirewallAction.Block, FirewallDirection.Inbound, ALL_PROFILES) {
                Description     = $"Created on {now:F}, to be deleted on {unbanTime:F} (offense #{clientFailureHistory.banCount:N0}).",
                Grouping        = GROUP_NAME,
                RemoteAddresses = new IAddress[] { new NetworkAddress(subnet.Network, subnet.Netmask) }
            };

            if (!configuration.isDryRun) {
                firewall.Rules.Add(rule);
            }

            JobManager.AddJob(() => unban(subnet), schedule => schedule.ToRunOnceAt(unbanTime));

            LOGGER.Info("Added Windows Firewall rule to block inbound traffic from {0}, which will be removed at {1:F} (in {2:g}).", subnet, unbanTime, configuration.banPeriod);

            LOGGER.Trace("Clearing internal history of failures for {0} now that a firewall rule has been created.", subnet);

            if (!configuration.isDryRun) {
                clientFailureHistory.clear();
            }
        }

        private void unban(IPNetwork subnet) {
            IEnumerable<FirewallWASRule> rulesToRemove = firewall.Rules.Where(isBanRule(subnet));
            foreach (FirewallWASRule rule in rulesToRemove) {
                LOGGER.Info("Ban has expired on subnet {0}, removing firewall rule {1}.", subnet, rule.Name);
                if (!configuration.isDryRun) {
                    firewall.Rules.Remove(rule);
                }
            }
        }

        private static Func<FirewallWASRule, bool> isBanRule(IPNetwork? subnet = null) {
            string? ruleName = subnet is not null ? getRuleName(subnet) : null;
            return rule => rule.Grouping == GROUP_NAME && (ruleName is null || ruleName == rule.Name);
        }

        private static string getRuleName(IPNetwork ipAddress) => $"Banned {ipAddress}";

        public void Dispose() {
            eventLogListener.failure -= onFailure;
            JobManager.Stop();
            JobManager.RemoveAllJobs();
        }

    }

}