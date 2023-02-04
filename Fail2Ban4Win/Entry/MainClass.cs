#nullable enable

using System;
using System.ServiceProcess;
using System.Threading;

namespace Fail2Ban4Win.Entry;

public static class MainClass {

    private static readonly ManualResetEvent UNBLOCK_MAIN_THREAD = new(false);

    private static WindowsService service = null!;

    public static void Main(string[] args) {
        service = new WindowsService();
        if (isBackgroundService) {
            ServiceBase.Run(service);
        } else {
            Console.CancelKeyPress += onCtrlC;

            service.startManually(args);

            UNBLOCK_MAIN_THREAD.WaitOne(); //block while service runs, then exit once user hits Ctrl+C

            service.Dispose();
        }
    }

    internal static void onCtrlC(object? sender, ConsoleCancelEventArgs eventArgs) {
        eventArgs.Cancel = true;
        stop();
    }

    public static void stop() {
        if (isBackgroundService) {
            service.Stop();
        } else {
            service.stopManually();
            UNBLOCK_MAIN_THREAD.Set();
        }
    }

    private static bool isBackgroundService => !Environment.UserInteractive;

}