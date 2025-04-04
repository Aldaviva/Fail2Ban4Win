#nullable enable

using Fail2Ban4Win.Config;
using Fail2Ban4Win.Facades;
using Fail2Ban4Win.Services;
using FakeItEasy;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using Tests.Logging;
using WindowsFirewallHelper;
using WindowsFirewallHelper.Addresses;
using WindowsFirewallHelper.Collections;
using WindowsFirewallHelper.FirewallRules;
using Xunit;
using Xunit.Abstractions;

namespace Tests.Services;

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
        maxAllowedFailures            = MAX_ALLOWED_FAILURES,
        neverBanSubnets               = [IPNetwork2.Parse("73.202.12.148/32")]
    };

    private readonly FakeFirewallRulesCollection firewallRules  = [];
    private readonly FirewallFacade              firewallFacade = A.Fake<FirewallFacade>();

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
    public void dontBanReservedAddressByDefault() {
        IPAddress reservedAddress = IPAddress.Parse("192.168.1.1");
        for (int i = 0; i < MAX_ALLOWED_FAILURES + 1; i++) {
            eventLogListener.failure += Raise.With(null, reservedAddress);
        }

        Assert.Empty(firewallRules);
    }

    [Fact]
    public void dontBanReservedAddressWhenConfigured() {
        configuration.neverBanReservedSubnets = true;

        IPAddress reservedAddress = IPAddress.Parse("192.168.1.1");
        for (int i = 0; i < MAX_ALLOWED_FAILURES + 1; i++) {
            eventLogListener.failure += Raise.With(null, reservedAddress);
        }

        Assert.Empty(firewallRules);
    }

    [Fact]
    public void banReservedAddressWhenConfigured() {
        configuration.neverBanReservedSubnets = false;

        IPAddress reservedAddress = IPAddress.Parse("192.168.1.1");
        for (int i = 0; i < MAX_ALLOWED_FAILURES + 1; i++) {
            eventLogListener.failure += Raise.With(null, reservedAddress);
        }

        Assert.NotEmpty(firewallRules);
    }

    [Fact]
    public void dontBanLoopbackAddress() {
        IPAddress reservedAddress = IPAddress.Parse("127.0.0.1");
        for (int i = 0; i < MAX_ALLOWED_FAILURES + 1; i++) {
            eventLogListener.failure += Raise.With(null, reservedAddress);
        }

        Assert.Empty(firewallRules);
    }

    [Fact]
    public void dontBanWhitelistedAddress() {
        IPAddress reservedAddress = IPAddress.Parse("73.202.12.148");
        for (int i = 0; i < MAX_ALLOWED_FAILURES + 1; i++) {
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
        FirewallWASRule actual = Assert.Single(firewallRules);
        Assert.True(actual.IsEnable);
        Assert.Equal("Banned 192.0.2.0/24", actual.Name);
        Assert.Equal("Fail2Ban4Win", actual.Grouping);
        Assert.Equal(FirewallAction.Block, actual.Action);
        Assert.Equal(FirewallDirection.Inbound, actual.Direction);
        Assert.Equal(NetworkAddress.Parse("192.0.2.0/24"), actual.RemoteAddresses[0]);
    }

    [Fact]
    public void dontBanWhenSameRuleAlreadyExists() {
        for (int i = 0; i < 2 * (MAX_ALLOWED_FAILURES + 1); i++) {
            eventLogListener.failure += Raise.With(null, SOURCE_ADDRESS);
        }

        Assert.NotEmpty(firewallRules);
        FirewallWASRule actual = Assert.Single(firewallRules);
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

        BanManagerImpl manager = new(eventLogListener, configuration, firewallFacade);

        for (int i = 0; i < MAX_ALLOWED_FAILURES + 1; i++) {
            eventLogListener.failure += Raise.With(null, SOURCE_ADDRESS);
        }

        Assert.Empty(firewallRules);

        manager.Dispose();
    }

    [Fact]
    public void deleteExistingRulesOnStartup() {
        banManager.Dispose();

        firewallRules.Add(new FirewallWASRule("deleteme1", FirewallAction.Block, FirewallDirection.Inbound, FirewallProfiles.Public) { Grouping = "Fail2Ban4Win" });
        firewallRules.Add(new FirewallWASRule("deleteme2", FirewallAction.Block, FirewallDirection.Inbound, FirewallProfiles.Public) { Grouping = "Fail2Ban4Win" });

        CountdownEvent rulesRemoved = new(firewallRules.Count);
        firewallRules.ruleRemoved += (_, _) => rulesRemoved.Signal();

        Assert.NotEmpty(firewallRules);

        BanManagerImpl manager = new(eventLogListener, configuration, firewallFacade);

        Assert.NotEmpty(firewallRules);

        //deletion runs asynchronously to speed up startup
        rulesRemoved.Wait(TimeSpan.FromSeconds(10));

        Assert.Empty(firewallRules);

        manager.Dispose();
    }

    [Fact]
    public void unbanAfterBanExpired() {
        ICollection<IPAddress> sourceAddresses = [
            IPAddress.Parse("198.51.100.1"),
            IPAddress.Parse("101.206.243.0")
        ];

        CountdownEvent rulesRemoved = new(sourceAddresses.Count);
        firewallRules.ruleRemoved += (_, _) => rulesRemoved.Signal();

        foreach (IPAddress sourceAddress in sourceAddresses) {
            for (int i = 0; i < MAX_ALLOWED_FAILURES + 1; i++) {
                eventLogListener.failure += Raise.With(null, sourceAddress);
            }
        }

        Assert.NotEmpty(firewallRules);

        rulesRemoved.Wait(TimeSpan.FromSeconds(10));

        testOutput.WriteLine("banPeriod = {0}", configuration.banPeriod);
        Assert.Empty(firewallRules);
    }

    [Fact]
    public void unbanCatchesAndLogsExceptions() {
        IPAddress      sourceAddress = IPAddress.Parse("103.153.254.0");
        CountdownEvent rulesRemoved  = new(1);

        var throwingFirewallRules = A.Fake<IFirewallWASRulesCollection<FirewallWASRule>>(options => options.Wrapping(firewallRules));
        A.CallTo(() => throwingFirewallRules.Remove(A<FirewallWASRule>._)).Throws(() => {
            rulesRemoved.Signal();
            throw new InvalidOperationException("This is intentionally thrown as part of a test");
        });
        A.CallTo(() => firewallFacade.Rules).Returns(throwingFirewallRules);

        for (int i = 0; i < MAX_ALLOWED_FAILURES + 1; i++) {
            eventLogListener.failure += Raise.With(null, sourceAddress);
        }

        Assert.NotEmpty(firewallRules);

        rulesRemoved.Wait(TimeSpan.FromSeconds(10));

        testOutput.WriteLine("banPeriod = {0}", configuration.banPeriod);
        Assert.NotEmpty(firewallRules);
    }

    [Theory]
    [MemberData(nameof(BAN_DURATION_DATA))]
    public void banDuration(int offense, double coefficient, TimeSpan expectedDuration) {
        configuration.banPeriod                     = TimeSpan.FromMinutes(1);
        configuration.banRepeatedOffenseCoefficient = coefficient;

        TimeSpan actual = banManager.getUnbanDuration(offense);

        Assert.Equal(expectedDuration, actual);
    }

    public static readonly IEnumerable<object[]> BAN_DURATION_DATA = [
        [1, 1.0, TimeSpan.FromMinutes(1)],
        [2, 1.0, TimeSpan.FromMinutes(2)],
        [3, 1.0, TimeSpan.FromMinutes(3)],
        [4, 1.0, TimeSpan.FromMinutes(4)],
        [5, 1.0, TimeSpan.FromMinutes(4)],
        [6, 1.0, TimeSpan.FromMinutes(4)],
        [1, 1.5, TimeSpan.FromMinutes(1)],
        [2, 1.5, TimeSpan.FromMinutes(2.5)],
        [3, 1.5, TimeSpan.FromMinutes(4)],
        [4, 1.5, TimeSpan.FromMinutes(5.5)],
        [5, 1.5, TimeSpan.FromMinutes(5.5)],
        [6, 1.5, TimeSpan.FromMinutes(5.5)],
        [1, 2.0, TimeSpan.FromMinutes(1)],
        [2, 2.0, TimeSpan.FromMinutes(3)],
        [3, 2.0, TimeSpan.FromMinutes(5)],
        [4, 2.0, TimeSpan.FromMinutes(7)],
        [5, 2.0, TimeSpan.FromMinutes(7)],
        [6, 2.0, TimeSpan.FromMinutes(7)],
    ];

    [Fact]
    public void longDelaysDoNotCrash() {
        configuration.banPeriod     = TimeSpan.FromDays(364);
        configuration.failureWindow = TimeSpan.FromHours(1);

        IPAddress sourceAddress = IPAddress.Parse("198.51.100.1");
        for (int i = 0; i < configuration.maxAllowedFailures + 1; i++) {
            eventLogListener.failure += Raise.With(null, sourceAddress);
        }

        Assert.NotEmpty(firewallRules);
    }

    private class FakeFirewallRulesCollection: List<FirewallWASRule>, IFirewallWASRulesCollection<FirewallWASRule> {

        private readonly object mutex = new();

        public FirewallWASRule? this[string name] => this.FirstOrDefault(rule => rule.Name == name);
        public event EventHandler<FirewallWASRule>? ruleRemoved;

        public bool Remove(string name) {
            FirewallWASRule? ruleToRemove;
            bool             result;

            lock (mutex) {
                ruleToRemove = this[name];
                result       = ruleToRemove is not null && Remove(ruleToRemove);
            }

            if (result) {
                ruleRemoved?.Invoke(this, ruleToRemove!);
            }

            return result;
        }

        void ICollection<FirewallWASRule>.Add(FirewallWASRule item) {
            lock (mutex) {
                Add(item);
            }
        }

        void ICollection<FirewallWASRule>.Clear() {
            lock (mutex) {
                Clear();
            }
        }

        bool ICollection<FirewallWASRule>.Remove(FirewallWASRule item) {
            bool result;

            lock (mutex) {
                result = Remove(item);
            }

            if (result) {
                ruleRemoved?.Invoke(this, item);
            }

            return result;
        }

    }

    public void Dispose() {
        banManager.Dispose();
        eventLogListener.Dispose();
    }

}