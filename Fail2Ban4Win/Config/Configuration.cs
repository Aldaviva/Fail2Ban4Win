using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Configuration;

#nullable enable

namespace Fail2Ban4Win.Config {

    public class Configuration {

        public int maxAllowedFailures { get; set; }
        public TimeSpan failureWindow { get; set; }

        public TimeSpan banPeriod { get; set; }
        public byte? banCidr { get; set; }
        public IEnumerable<IPNetwork>? neverBanSubnets { get; set; }
        public IEnumerable<EventLogSelector> eventLogSelectors { get; set; } = null!;

        public override string ToString() =>
            $"{nameof(maxAllowedFailures)}: {maxAllowedFailures}, {nameof(failureWindow)}: {failureWindow}, {nameof(banPeriod)}: {banPeriod}, {nameof(banCidr)}: {banCidr}, {nameof(neverBanSubnets)}: [{{{string.Join("}, {", neverBanSubnets ?? new IPNetwork[0])}}}], {nameof(eventLogSelectors)}: [{{{string.Join("}, {", eventLogSelectors)}}}]";

    }

    public class EventLogSelector {

        public string logName { get; set; } = null!;
        public string? source { get; set; }
        public int eventId { get; set; }
        public Regex? ipAddressPattern { get; set; }
        public string? ipAddressEventDataName { get; set; }

        public override string ToString() =>
            $"{nameof(logName)}: {logName}, {nameof(source)}: {source}, {nameof(eventId)}: {eventId}, {nameof(ipAddressPattern)}: {ipAddressPattern}, {nameof(ipAddressEventDataName)}: {ipAddressEventDataName}";

    }

    public class Test {

        public static void Main() {
            string json = @"{
	""maxAllowedFailures"": 9,
	""failureWindow"": ""1.00:00:00"",
	""banPeriod"": ""1.00:00:00"",
    ""banCidr"": 24,
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
	]
}";
            Stream jsonStream = new MemoryStream(Encoding.UTF8.GetBytes(json));
            IConfigurationRoot configuration = new ConfigurationBuilder()
                .AddJsonStream(jsonStream)
                .Build();
            var deserialized = configuration.Get<Configuration>();
            Console.WriteLine(deserialized);
        }

    }

}