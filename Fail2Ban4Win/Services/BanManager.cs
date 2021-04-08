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
using FluentScheduler;

#nullable enable

namespace Fail2Ban4Win.Services {

    public interface BanManager: IDisposable { }

    public class BanManagerImpl: BanManager {

        private const FirewallProfiles ALL_PROFILES = FirewallProfiles.Domain | FirewallProfiles.Private | FirewallProfiles.Public;
        private const string           GROUP_NAME   = "Fail2Ban4Win";

        public static readonly IPNetwork LOOPBACK = IPNetwork.Parse("127.0.0.1", 8);

        private readonly EventLogListener eventLogListener;
        private readonly Configuration    configuration;

        private readonly FirewallWAS firewall = FirewallWAS.Instance;

        private readonly ConcurrentDictionary<IPNetwork, ConcurrentQueue<DateTimeOffset>> failures = new();

        public BanManagerImpl(EventLogListener eventLogListener, Configuration configuration) {
            this.eventLogListener = eventLogListener;
            this.configuration    = configuration;

            JobManager.Initialize(new Registry());

            IEnumerable<FirewallWASRule> oldRules = firewall.Rules.Where(rule => rule.Grouping == GROUP_NAME);
            foreach (FirewallWASRule oldRule in oldRules) {
                firewall.Rules.Remove(oldRule);
            }

            eventLogListener.failure += onFailure;
        }

        private void onFailure(object sender, IPAddress ipAddress) {
            IPNetwork subnet = IPNetwork.Parse(ipAddress, IPNetwork.ToNetmask(configuration.banCidr ?? 32, AddressFamily.InterNetwork));

            ConcurrentQueue<DateTimeOffset> failuresForSubnet = failures.GetOrAdd(subnet, new ConcurrentQueue<DateTimeOffset>());
            failuresForSubnet.Enqueue(DateTimeOffset.Now);

            if (shouldBan(subnet)) {
                ban(subnet);
            }
        }

        private bool shouldBan(IPNetwork subnet) {
            if (subnet.IsIANAReserved() || LOOPBACK.Contains(subnet) || (configuration.neverBanSubnets?.Any(neverBan => neverBan.Overlap(subnet)) ?? false)) {
                return false;
            }

            failures.TryGetValue(subnet, out ConcurrentQueue<DateTimeOffset>? failuresForAddress);
            if (failuresForAddress is not null) {
                DateTimeOffset now                 = DateTimeOffset.Now;
                bool           enoughFailuresToBan = failuresForAddress.Count(failureTime => now - configuration.failureWindow < failureTime) > configuration.maxAllowedFailures;
                return enoughFailuresToBan;
            } else {
                return false;
            }
        }

        private void ban(IPNetwork subnet) {
            string ruleName = getRuleName(subnet);

            if (!firewall.Rules.Any(isBanRuleForSubnet(subnet))) {
                DateTime now = DateTime.Now;
                FirewallWASRule rule = new FirewallWASRuleWin7(ruleName, FirewallAction.Block, FirewallDirection.Inbound, ALL_PROFILES) {
                    Description     = $"Created by Fail2Ban4Win on {now:F}.",
                    Grouping        = GROUP_NAME,
                    RemoteAddresses = new IAddress[] { new NetworkAddress(subnet.Network, subnet.Netmask) }
                };
                firewall.Rules.Add(rule);

                JobManager.AddJob(() => unban(subnet), schedule => schedule.ToRunOnceAt(now + configuration.banPeriod));
            }
        }

        private void unban(IPNetwork subnet) {
            IEnumerable<FirewallWASRule> rulesToRemove = firewall.Rules.Where(isBanRuleForSubnet(subnet));
            foreach (FirewallWASRule rule in rulesToRemove) {
                firewall.Rules.Remove(rule);
            }
        }

        private static Func<FirewallWASRule, bool> isBanRuleForSubnet(IPNetwork subnet) {
            string ruleName = getRuleName(subnet);
            return rule => rule.Name == ruleName && rule.Grouping == GROUP_NAME;
        }

        private static string getRuleName(IPNetwork ipAddress) => $"Banned {ipAddress}";

        public void Dispose() {
            eventLogListener.failure -= onFailure;
            JobManager.Stop();
            JobManager.RemoveAllJobs();
        }

    }

}