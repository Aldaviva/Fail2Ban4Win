using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Fail2Ban4Win.Entry;
using Tests.Logging;
using Xunit;
using Xunit.Abstractions;

#nullable enable

namespace Tests.Entry {

    public class MainClassTest: IDisposable {

        public MainClassTest(ITestOutputHelper testOutputHelper) {
            XunitTestOutputTarget.start(testOutputHelper);
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
        public async Task start() {
            File.WriteAllText("configuration.json", JSON, Encoding.UTF8);

            Task main = Task.Run(() => MainClass.Main(new string[0]));

            await Task.Delay(200);

            MainClass.stop();

            await main;
        }

        public void Dispose() {
            File.Delete("configuration.json");
            File.Move("configuration.json.backup", "configuration.json");
        }

    }

}