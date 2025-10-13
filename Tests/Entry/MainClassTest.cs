#nullable enable

using Fail2Ban4Win.Entry;
using System;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using Tests.Logging;
using Windows.Win32;
using Xunit;
using Xunit.Abstractions;

namespace Tests.Entry;

public class MainClassTest: IDisposable {

    private readonly ITestOutputHelper testOutputHelper;

    public MainClassTest(ITestOutputHelper testOutputHelper) {
        this.testOutputHelper = testOutputHelper;
        XunitTestOutputTarget.start(testOutputHelper);
        File.Delete("configuration.json.backup");
        File.Move("configuration.json", "configuration.json.backup");
        File.WriteAllText("configuration.json", JSON, new UTF8Encoding(false, true));
    }

    private const string JSON =
        """
        {
        	"maxAllowedFailures": 9,
        	"failureWindow": "1.00:00:00",
        	"banPeriod": "1.00:00:00",
            "banSubnetBits": 24,
            "banRepeatedOffenseCoefficient": 1,
            "banRepeatedOffenseMax": 4,
            "neverBanSubnets": [
                "127.0.0.1/8",
                "192.168.1.0/24",
                "67.210.32.33",
                "73.202.12.148"
            ],
        	"eventLogSelectors": [
        		{
        			"logName": "Security",
        			"eventId": 4625,
        			"ipAddressEventDataName": "IpAddress"
        		}, {
        			"logName": "Application",
        			"source": "sshd",
        			"eventId": 0,
        			"ipAddressPattern": "^sshd: PID \\d+: Failed password for(?: invalid user)? \\S+ from (?<ipAddress>(?:\\d{1,3}\\.){3}\\d{1,3}) port \\d+ ssh\\d?$"
        		}
        	],
            "isDryRun": true,
            "logLevel": "info"
        }
        """;

    [Fact]
    public async Task start() {
        Task main = Task.Run(() => MainClass.Main(Array.Empty<string>()));

        await Task.Delay(200);

        MainClass.stop();

        await main;
    }

    [Fact]
    public async Task stopWithCtrlC() {
        Task main = Task.Run(() => MainClass.Main(Array.Empty<string>()));

        await Task.Delay(200);

        ConsoleCancelEventArgs consoleCancelEventArgs = createInstance<ConsoleCancelEventArgs>(ConsoleSpecialKey.ControlC);

        MainClass.onCtrlC(null, consoleCancelEventArgs);

        await main;
    }

    /// <summary>
    /// Force the app to start in background service mode with a custom WindowStation so that Environment.UserInteractive is false, which prevents it from erroring out with a dialog box
    /// </summary>
    /// <returns></returns>
    [Fact]
    public async Task startService() {
        const uint WINSTA_ALL_ACCESS = 0x37F;

        CloseWindowStationSafeHandle originalWindowStation = PInvoke.GetProcessWindowStation_SafeHandle();
        try {
            testOutputHelper.WriteLine("Creating new window station.");
            using CloseWindowStationSafeHandle nonInteractiveWindowStation = PInvoke.CreateWindowStation("hargle", 0, WINSTA_ALL_ACCESS, null);

            PInvoke.SetProcessWindowStation(nonInteractiveWindowStation);

            Task main = Task.Run(() => MainClass.Main(Array.Empty<string>()));

            await Task.Delay(200);

            MainClass.stop();

            await main;

        } finally {
            PInvoke.SetProcessWindowStation(originalWindowStation);
        }
    }

    public void Dispose() {
        File.Delete("configuration.json");
        File.Move("configuration.json.backup", "configuration.json");
    }

    /// <summary>
    /// <para>Construct instance of a class which has an internal constructor using reflection.</para>
    /// <para>Source: https://stackoverflow.com/a/30728269/979493</para>
    /// </summary>
    /// <typeparam name="T">Class of instance to construct</typeparam>
    /// <param name="args">Arguments to pass to the contructor</param>
    /// <returns>A new instance of <typeparamref name="T"/></returns>
    public static T createInstance<T>(params object[] args) {
        Type type = typeof(T);
        return (T) type.Assembly.CreateInstance(type.FullName, false, BindingFlags.Instance | BindingFlags.NonPublic, null, args, null, null);
    }

}