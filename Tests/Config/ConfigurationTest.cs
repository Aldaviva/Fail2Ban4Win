using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using Fail2Ban4Win.Config;
using Fail2Ban4Win.Injection;
using LightInject;
using Xunit;
using Xunit.Abstractions;
using LogLevel = NLog.LogLevel;

#nullable enable

namespace Tests.Config {

    [CollectionDefinition(nameof(ConfigurationTest), DisableParallelization = true)]
    [Collection(nameof(ConfigurationTest))]
    public class ConfigurationTest: IDisposable {

        private readonly ITestOutputHelper testOutputHelper;

        public ConfigurationTest(ITestOutputHelper testOutputHelper) {
            this.testOutputHelper = testOutputHelper;
            File.Move("configuration.json", "configuration.json.backup");
        }

        private const string JSON = @"{
	""maxAllowedFailures"": 9,
	""failureWindow"": ""1.00:00:00"",
	""banPeriod"": ""1.00:00:00"",
    ""banSubnetBits"": 24,
    ""banRepeatedOffenseCoefficient"": 1,
    ""banRepeatedOffenseMax"": 4,
    ""neverBanSubnets"": [
        ""127.0.0.1/8"",
        ""192.168.1.0/24"",
        ""67.210.32.33"",
        ""73.202.12.148""
    ],
	""eventLogSelectors"": [
		{
			""logName"": ""Security"",
			""eventId"": 4625,
			""ipAddressEventDataName"": ""IpAddress""
		}, {
			""logName"": ""Application"",
			""source"": ""sshd"",
			""eventId"": 0,
			""ipAddressPattern"": ""^sshd: PID \\d+: Failed password for(?: invalid user)? \\S+ from (?<ipAddress>(?:\\d{1,3}\\.){3}\\d{1,3}) port \\d+ ssh\\d?$""
		}
	],
    ""isDryRun"": true,
    ""logLevel"": ""info""
}";

        [Fact]
        public void parse() {
            File.WriteAllText("configuration.json", JSON, Encoding.UTF8);
            testOutputHelper.WriteLine("Wrote {0}", Path.GetFullPath("configuration.json"));

            using ServiceContainer context = new();
            context.RegisterFrom<ConfigurationModule>();
            using Scope scope = context.BeginScope();

            var actual = scope.GetInstance<Configuration>();

            Assert.Equal(9, actual.maxAllowedFailures);
            Assert.Equal(TimeSpan.FromDays(1), actual.failureWindow);
            Assert.Equal(TimeSpan.FromDays(1), actual.banPeriod);
            Assert.Equal(24, actual.banSubnetBits!.Value);
            Assert.Equal(1, actual.banRepeatedOffenseCoefficient!.Value);
            Assert.Equal(4, actual.banRepeatedOffenseMax!.Value);
            Assert.True(actual.isDryRun);
            Assert.Equal(LogLevel.Info, actual.logLevel);
            Assert.Contains(IPNetwork.Parse("127.0.0.1/8"), actual.neverBanSubnets!);
            Assert.Contains(IPNetwork.Parse("192.168.1.0/24"), actual.neverBanSubnets!);
            Assert.Contains(IPNetwork.Parse("67.210.32.33/32"), actual.neverBanSubnets!);
            Assert.Contains(IPNetwork.Parse("73.202.12.148/32"), actual.neverBanSubnets!);
            Assert.NotNull(actual.ToString());

            EventLogSelector[] actualSelectors = actual.eventLogSelectors.ToArray();
            Assert.Equal(2, actualSelectors.Length);

            EventLogSelector rdpSelector = actualSelectors[0];
            Assert.Equal("Security", rdpSelector.logName);
            Assert.Equal(4625, rdpSelector.eventId);
            Assert.Equal("IpAddress", rdpSelector.ipAddressEventDataName);
            Assert.Null(rdpSelector.ipAddressPattern);
            Assert.Null(rdpSelector.source);
            Assert.NotNull(rdpSelector.ToString());

            EventLogSelector cygwinSshdSelector = actualSelectors[1];
            Assert.Equal("Application", cygwinSshdSelector.logName);
            Assert.Equal(0, cygwinSshdSelector.eventId);
            Assert.Null(cygwinSshdSelector.ipAddressEventDataName);
            Assert.Equal(new Regex(@"^sshd: PID \d+: Failed password for(?: invalid user)? \S+ from (?<ipAddress>(?:\d{1,3}\.){3}\d{1,3}) port \d+ ssh\d?$").ToString(),
                cygwinSshdSelector.ipAddressPattern!.ToString());
            Assert.Equal("sshd", cygwinSshdSelector.source);
            Assert.NotNull(cygwinSshdSelector.ToString());
        }

        public void Dispose() {
            File.Delete("configuration.json");
            File.Move("configuration.json.backup", "configuration.json");
        }

    }

}