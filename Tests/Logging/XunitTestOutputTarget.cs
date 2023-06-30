using NLog;
using NLog.Config;
using NLog.Targets;
using Xunit.Abstractions;

namespace Tests.Logging;

[Target("xUnit")]
public class XunitTestOutputTarget: TargetWithLayout {

    [RequiredParameter]
    public ITestOutputHelper testOutputHelper { get; set; }

    protected override void Write(LogEventInfo logEvent) {
        string logMessage = RenderLogEvent(Layout, logEvent);
        testOutputHelper.WriteLine(logMessage);
    }

    public static void start(ITestOutputHelper testOutputHelper) {
        LogManager.Setup().LoadConfiguration(builder => builder.ForLogger(LogLevel.Trace).WriteTo(new XunitTestOutputTarget { testOutputHelper = testOutputHelper }));
    }

}