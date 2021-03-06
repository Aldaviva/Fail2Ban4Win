using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using WindowsFirewallHelper;
using WindowsFirewallHelper.Addresses;
using WindowsFirewallHelper.Collections;
using WindowsFirewallHelper.FirewallRules;
using Fail2Ban4Win.Config;
using Fail2Ban4Win.Facades;
using Fail2Ban4Win.Services;
using FakeItEasy;
using NLog;
using Tests.Logging;
using Xunit;
using Xunit.Abstractions;

#nullable enable

namespace Tests.Services {

    public class BanManagerTest: IDisposable {

        private static readonly IPAddress SOURCE_ADDRESS = IPAddress.Parse("192.0.2.0");

        private const int MAX_ALLOWED_FAILURES = 2;

        private readonly BanManagerImpl    banManager;
        private readonly EventLogListener  eventLogListener = A.Fake<EventLogListener>();
        private readonly ITestOutputHelper testOutput;

        private readonly Configuration configuration = new() {
            isDryRun                      = false,
            failureWindow                 = TimeSpan.FromMilliseconds(50),
            banPeriod                     = TimeSpan.FromMilliseconds(200),
            banSubnetBits                 = 8,
            banRepeatedOffenseCoefficient = 1,
            banRepeatedOffenseMax         = 4,
            logLevel                      = LogLevel.Trace,
            maxAllowedFailures            = MAX_ALLOWED_FAILURES,
            neverBanSubnets               = new[] { IPNetwork.Parse("73.202.12.148/32") }
        };

        private readonly IFirewallWASRulesCollection<FirewallWASRule> firewallRules  = new FakeFirewallRulesCollection();
        private readonly FirewallFacade                               firewallFacade = A.Fake<FirewallFacade>();

        public BanManagerTest(ITestOutputHelper testOutput) {
            this.testOutput = testOutput;
            XunitTestOutputTarget.start(testOutput);

            A.CallTo(() => firewallFacade.Rules).Returns(firewallRules);
            banManager = new BanManagerImpl(eventLogListener, configuration, firewallFacade);
        }

        [Fact]
        public void dontBanAfterInsufficientFailures() {
            for (int i = 0; i < MAX_ALLOWED_FAILURES; i++) {
                eventLogListener.failure += Raise.With(null, SOURCE_ADDRESS);
            }

            Assert.Empty(firewallRules);
        }

        [Fact]
        public void dontBanReservedAddress() {
            IPAddress reservedAddress = IPAddress.Parse("192.168.1.1");
            for (int i = 0; i < MAX_ALLOWED_FAILURES; i++) {
                eventLogListener.failure += Raise.With(null, reservedAddress);
            }

            Assert.Empty(firewallRules);
        }

        [Fact]
        public void dontBanLoopbackAddress() {
            IPAddress reservedAddress = IPAddress.Parse("127.0.0.1");
            for (int i = 0; i < MAX_ALLOWED_FAILURES; i++) {
                eventLogListener.failure += Raise.With(null, reservedAddress);
            }

            Assert.Empty(firewallRules);
        }

        [Fact]
        public void dontBanWhitelistedAddress() {
            IPAddress reservedAddress = IPAddress.Parse("73.202.12.148");
            for (int i = 0; i < MAX_ALLOWED_FAILURES; i++) {
                eventLogListener.failure += Raise.With(null, reservedAddress);
            }

            Assert.Empty(firewallRules);
        }

        [Fact]
        public void bansAfterEnoughFailures() {
            for (int i = 0; i < MAX_ALLOWED_FAILURES + 1; i++) {
                eventLogListener.failure += Raise.With(null, SOURCE_ADDRESS);
            }

            Assert.NotEmpty(firewallRules);
            FirewallWASRule actual = firewallRules.First();
            Assert.True(actual.IsEnable);
            Assert.Equal("Banned 192.0.2.0/24", actual.Name);
            Assert.Equal("Fail2Ban4Win", actual.Grouping);
            Assert.Equal(FirewallAction.Block, actual.Action);
            Assert.Equal(FirewallDirection.Inbound, actual.Direction);
            Assert.Equal(NetworkAddress.Parse("192.0.2.0/24"), actual.RemoteAddresses[0]);
        }

        [Fact]
        public void dontBanInDryRunMode() {
            banManager.Dispose();

            configuration.isDryRun = true;

            var manager = new BanManagerImpl(eventLogListener, configuration, firewallFacade);

            for (int i = 0; i < MAX_ALLOWED_FAILURES + 1; i++) {
                eventLogListener.failure += Raise.With(null, SOURCE_ADDRESS);
            }

            Assert.Empty(firewallRules);

            manager.Dispose();
        }

        [Fact]
        public async Task deleteExistingRulesOnStartup() {
            banManager.Dispose();

            firewallRules.Add(new FirewallWASRule("deleteme1", FirewallAction.Block, FirewallDirection.Inbound, FirewallProfiles.Public) { Grouping = "Fail2Ban4Win" });
            firewallRules.Add(new FirewallWASRule("deleteme2", FirewallAction.Block, FirewallDirection.Inbound, FirewallProfiles.Public) { Grouping = "Fail2Ban4Win" });

            Assert.NotEmpty(firewallRules);

            var manager = new BanManagerImpl(eventLogListener, configuration, firewallFacade);

            Assert.NotEmpty(firewallRules);

            //deletion runs asynchronously to speed up startup
            await Task.Delay(100);

            Assert.Empty(firewallRules);

            manager.Dispose();
        }

        [Fact]
        public async Task unbanAfterBanExpired() {
            IPAddress sourceAddress = IPAddress.Parse("198.51.100.1");
            for (int i = 0; i < MAX_ALLOWED_FAILURES + 1; i++) {
                eventLogListener.failure += Raise.With(null, sourceAddress);
            }

            Assert.NotEmpty(firewallRules);

            await Task.Delay((int) configuration.banPeriod.TotalMilliseconds * 2);

            testOutput.WriteLine("banPeriod = {0}", configuration.banPeriod);
            Assert.Empty(firewallRules);
        }

        [Theory]
        [MemberData(nameof(BAN_DURATION_DATA))]
        public void banDuration(int offense, TimeSpan expectedDuration) {
            configuration.banPeriod = TimeSpan.FromMinutes(1);

            TimeSpan actual = banManager.getUnbanDuration(offense);

            Assert.Equal(expectedDuration, actual);
        }

        public static readonly IEnumerable<object[]> BAN_DURATION_DATA = new[] {
            new object[] { 1, TimeSpan.FromMinutes(1) },
            new object[] { 2, TimeSpan.FromMinutes(2) },
            new object[] { 3, TimeSpan.FromMinutes(3) },
            new object[] { 4, TimeSpan.FromMinutes(4) },
            new object[] { 5, TimeSpan.FromMinutes(4) },
            new object[] { 6, TimeSpan.FromMinutes(4) }
        };

        private class FakeFirewallRulesCollection: List<FirewallWASRule>, IFirewallWASRulesCollection<FirewallWASRule> {

            public FirewallWASRule? this[string name] => this.FirstOrDefault(rule => rule.Name == name);

            public bool Remove(string name) {
                if (this[name] is { } ruleToRemove) {
                    Remove(ruleToRemove);
                    return true;
                } else {
                    return false;
                }
            }

        }

        public void Dispose() {
            banManager.Dispose();
            eventLogListener.Dispose();
        }

    }

}