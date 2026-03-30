#nullable enable

using Fail2Ban4Win.Config;
using Fail2Ban4Win.Data;
using Fail2Ban4Win.Facades;
using Fail2Ban4Win.Plugins;
using Fail2Ban4Win.Services;
using FakeItEasy;
using FluentAssertions;
using Plugins;
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

    private const int MAX_ALLOWED_FAILURES = 2;

    private static readonly IPAddress SOURCE_ADDRESS = IPAddress.Parse("192.0.2.0");

    private readonly BanManagerImpl                      banManager;
    private readonly EventLogListener                    eventLogListener = A.Fake<EventLogListener>();
    private readonly IPluginManager<IFail2Ban4WinPlugin> pluginManager    = A.Fake<IPluginManager<IFail2Ban4WinPlugin>>();
    private readonly ITestOutputHelper                   testOutput;

    private readonly Configuration configuration = new() {
        isDryRun                      = false,
        failureWindow                 = TimeSpan.FromMilliseconds(50),
        banPeriod                     = TimeSpan.FromSeconds(1),
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
        banManager = new BanManagerImpl(eventLogListener, configuration, firewallFacade, pluginManager);
    }

    [Fact]
    public void dontBanAfterInsufficientFailures() {
        for (int i = 0; i < MAX_ALLOWED_FAILURES; i++) {
            eventLogListener.failure += Raise.With(null, new FailureParams(SOURCE_ADDRESS, null, "", 0, "", DateTimeOffset.UtcNow));
        }

        firewallRules.Should().BeEmpty();
    }

    [Fact]
    public void dontBanReservedAddressByDefault() {
        IPAddress reservedAddress = IPAddress.Parse("192.168.1.1");
        for (int i = 0; i < MAX_ALLOWED_FAILURES + 1; i++) {
            eventLogListener.failure += Raise.With(null, new FailureParams(reservedAddress, null, "", 0, "", DateTimeOffset.UtcNow));
        }

        firewallRules.Should().BeEmpty();
    }

    [Fact]
    public void dontBanReservedAddressWhenConfigured() {
        configuration.neverBanReservedSubnets = true;

        IPAddress reservedAddress = IPAddress.Parse("192.168.1.1");
        for (int i = 0; i < MAX_ALLOWED_FAILURES + 1; i++) {
            eventLogListener.failure += Raise.With(null, new FailureParams(reservedAddress, null, "", 0, "", DateTimeOffset.UtcNow));
        }

        firewallRules.Should().BeEmpty();
    }

    [Fact]
    public void banReservedAddressWhenConfigured() {
        configuration.neverBanReservedSubnets = false;

        IPAddress reservedAddress = IPAddress.Parse("192.168.1.1");
        for (int i = 0; i < MAX_ALLOWED_FAILURES + 1; i++) {
            eventLogListener.failure += Raise.With(null, new FailureParams(reservedAddress, null, "", 0, "", DateTimeOffset.UtcNow));
        }

        firewallRules.Should().NotBeEmpty();
    }

    [Fact]
    public void dontBanLoopbackAddress() {
        IPAddress reservedAddress = IPAddress.Parse("127.0.0.1");
        for (int i = 0; i < MAX_ALLOWED_FAILURES + 1; i++) {
            eventLogListener.failure += Raise.With(null, new FailureParams(reservedAddress, null, "", 0, "", DateTimeOffset.UtcNow));
        }

        firewallRules.Should().BeEmpty();
    }

    [Fact]
    public void dontBanWhitelistedAddress() {
        IPAddress reservedAddress = IPAddress.Parse("73.202.12.148");
        for (int i = 0; i < MAX_ALLOWED_FAILURES + 1; i++) {
            eventLogListener.failure += Raise.With(null, new FailureParams(reservedAddress, null, "", 0, "", DateTimeOffset.UtcNow));
        }

        firewallRules.Should().BeEmpty();
    }

    [Fact]
    public void bansAfterEnoughFailures() {
        for (int i = 0; i < MAX_ALLOWED_FAILURES + 1; i++) {
            eventLogListener.failure += Raise.With(null, new FailureParams(SOURCE_ADDRESS, null, "", 0, "", DateTimeOffset.UtcNow));
        }

        firewallRules.Should().HaveCount(1);
        FirewallWASRule actual = firewallRules[0];
        actual.IsEnable.Should().BeTrue();
        actual.Name.Should().Be("Banned 192.0.2.0/24");
        actual.Grouping.Should().Be("Fail2Ban4Win");
        actual.Action.Should().Be(FirewallAction.Block);
        actual.Direction.Should().Be(FirewallDirection.Inbound);
        actual.RemoteAddresses[0].Should().Be(NetworkAddress.Parse("192.0.2.0/24"));
    }

    [Fact]
    public void dontBanWhenSameRuleAlreadyExists() {
        for (int i = 0; i < 2 * (MAX_ALLOWED_FAILURES + 1); i++) {
            eventLogListener.failure += Raise.With(null, new FailureParams(SOURCE_ADDRESS, null, "", 0, "", DateTimeOffset.UtcNow));
        }

        firewallRules.Should().HaveCount(1);
        FirewallWASRule actual = firewallRules[0];
        actual.IsEnable.Should().BeTrue();
        actual.Name.Should().Be("Banned 192.0.2.0/24");
        actual.Grouping.Should().Be("Fail2Ban4Win");
        actual.Action.Should().Be(FirewallAction.Block);
        actual.Direction.Should().Be(FirewallDirection.Inbound);
        actual.RemoteAddresses[0].Should().Be(NetworkAddress.Parse("192.0.2.0/24"));
    }

    [Fact]
    public void dontBanInDryRunMode() {
        banManager.Dispose();

        configuration.isDryRun = true;

        BanManagerImpl manager = new(eventLogListener, configuration, firewallFacade, pluginManager);

        for (int i = 0; i < MAX_ALLOWED_FAILURES + 1; i++) {
            eventLogListener.failure += Raise.With(null, new FailureParams(SOURCE_ADDRESS, null, "", 0, "", DateTimeOffset.UtcNow));
        }

        firewallRules.Should().BeEmpty();

        manager.Dispose();
    }

    [Fact]
    public void deleteExistingRulesOnStartup() {
        banManager.Dispose();

        firewallRules.Add(new FirewallWASRule("deleteme1", FirewallAction.Block, FirewallDirection.Inbound, FirewallProfiles.Public) { Grouping = "Fail2Ban4Win" });
        firewallRules.Add(new FirewallWASRule("deleteme2", FirewallAction.Block, FirewallDirection.Inbound, FirewallProfiles.Public) { Grouping = "Fail2Ban4Win" });

        CountdownEvent rulesRemoved = new(firewallRules.Count);
        firewallRules.ruleRemoved += (_, _) => rulesRemoved.Signal();

        firewallRules.Should().NotBeEmpty();

        BanManagerImpl manager = new(eventLogListener, configuration, firewallFacade, pluginManager);

        firewallRules.Should().NotBeEmpty();

        //deletion runs asynchronously to speed up startup
        rulesRemoved.Wait(TimeSpan.FromSeconds(10));

        firewallRules.Should().BeEmpty();

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
                eventLogListener.failure += Raise.With(null, new FailureParams(sourceAddress, null, "", 0, "", DateTimeOffset.UtcNow));
            }
        }

        firewallRules.Should().NotBeEmpty();

        rulesRemoved.Wait(TimeSpan.FromSeconds(10));

        testOutput.WriteLine("banPeriod = {0}", configuration.banPeriod);
        firewallRules.Should().BeEmpty();
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
            eventLogListener.failure += Raise.With(null, new FailureParams(sourceAddress, null, "", 0, "", DateTimeOffset.UtcNow));
        }

        firewallRules.Should().NotBeEmpty();

        rulesRemoved.Wait(TimeSpan.FromSeconds(10));

        testOutput.WriteLine("banPeriod = {0}", configuration.banPeriod);
        firewallRules.Should().NotBeEmpty();
    }

    [Theory]
    [MemberData(nameof(BAN_DURATION_DATA))]
    public void banDuration(int offense, double coefficient, TimeSpan expectedDuration) {
        configuration.banPeriod                     = TimeSpan.FromMinutes(1);
        configuration.banRepeatedOffenseCoefficient = coefficient;

        TimeSpan actual = banManager.getUnbanDuration(offense);

        actual.Should().Be(expectedDuration);
    }

    public static readonly TheoryData<int, double, TimeSpan> BAN_DURATION_DATA = new() {
        { 1, 1.0, TimeSpan.FromMinutes(1) },
        { 2, 1.0, TimeSpan.FromMinutes(2) },
        { 3, 1.0, TimeSpan.FromMinutes(3) },
        { 4, 1.0, TimeSpan.FromMinutes(4) },
        { 5, 1.0, TimeSpan.FromMinutes(4) },
        { 6, 1.0, TimeSpan.FromMinutes(4) },
        { 1, 1.5, TimeSpan.FromMinutes(1) },
        { 2, 1.5, TimeSpan.FromMinutes(2.5) },
        { 3, 1.5, TimeSpan.FromMinutes(4) },
        { 4, 1.5, TimeSpan.FromMinutes(5.5) },
        { 5, 1.5, TimeSpan.FromMinutes(5.5) },
        { 6, 1.5, TimeSpan.FromMinutes(5.5) },
        { 1, 2.0, TimeSpan.FromMinutes(1) },
        { 2, 2.0, TimeSpan.FromMinutes(3) },
        { 3, 2.0, TimeSpan.FromMinutes(5) },
        { 4, 2.0, TimeSpan.FromMinutes(7) },
        { 5, 2.0, TimeSpan.FromMinutes(7) },
        { 6, 2.0, TimeSpan.FromMinutes(7) }
    };

    [Fact]
    public void longDelaysDoNotCrash() {
        configuration.banPeriod     = TimeSpan.FromDays(364);
        configuration.failureWindow = TimeSpan.FromHours(1);

        IPAddress sourceAddress = IPAddress.Parse("198.51.100.1");
        for (int i = 0; i < configuration.maxAllowedFailures + 1; i++) {
            eventLogListener.failure += Raise.With(null, new FailureParams(sourceAddress, null, "", 0, "", DateTimeOffset.UtcNow));
        }

        firewallRules.Should().NotBeEmpty();
    }

    [Fact]
    public void pluginBanCallback() {
        configuration.banPeriod = TimeSpan.FromHours(1);

        IFail2Ban4WinPlugin plugin = A.Fake<IFail2Ban4WinPlugin>();
        Captured<BanParams> bans   = A.Captured<BanParams>();
        A.CallTo(() => pluginManager.Plugins).Returns([plugin]);
        A.CallTo(() => plugin.OnSubnetBanned(bans._)).DoesNothing();

        for (int i = 0; i < MAX_ALLOWED_FAILURES + 1; i++) {
            eventLogListener.failure += Raise.With(null, new FailureParams(SOURCE_ADDRESS, null, "", 0, "", DateTimeOffset.UtcNow));
        }

        firewallRules.Should().NotBeEmpty();
        BanParams actualBan = bans.GetLastValue();
        actualBan.Subnet.Should().Be(IPNetwork2.Parse("192.0.2.0/24"));
        actualBan.Duration.Should().Be(TimeSpan.FromHours(1));
        actualBan.OffenseCount.Should().Be(1);
        actualBan.Start.Should().BeCloseTo(DateTimeOffset.Now, TimeSpan.FromSeconds(2));
        actualBan.End.Should().BeCloseTo(DateTimeOffset.Now + TimeSpan.FromHours(1), TimeSpan.FromSeconds(2));
    }

    [Fact]
    public void pluginUnbanCallback() {
        DateTimeOffset      now    = DateTimeOffset.Now;
        IFail2Ban4WinPlugin plugin = A.Fake<IFail2Ban4WinPlugin>();
        Captured<BanParams> bans   = A.Captured<BanParams>();
        A.CallTo(() => pluginManager.Plugins).Returns([plugin]);
        using ManualResetEventSlim callbackFired = new();
        A.CallTo(() => plugin.OnBanLifted(bans._)).Invokes(callbackFired.Set);

        for (int i = 0; i < MAX_ALLOWED_FAILURES + 1; i++) {
            eventLogListener.failure += Raise.With(null, new FailureParams(SOURCE_ADDRESS, null, "", 0, "", now));
        }

        callbackFired.Wait(TimeSpan.FromSeconds(10));

        BanParams actualBan = bans.GetLastValue();
        actualBan.Subnet.Should().Be(IPNetwork2.Parse("192.0.2.0/24"));
        actualBan.OffenseCount.Should().Be(1);
        actualBan.Start.Should().BeCloseTo(now, TimeSpan.FromSeconds(2), "start time");
        actualBan.End.Should().BeCloseTo(now + TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(2), "end time");
        actualBan.Duration.Should().Be(TimeSpan.FromSeconds(1), "duration");
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