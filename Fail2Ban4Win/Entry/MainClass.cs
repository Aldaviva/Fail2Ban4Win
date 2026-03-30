#nullable enable

using System.ServiceProcess;
using System.Threading;

namespace Fail2Ban4Win.Entry;

public static class MainClass {

    private static readonly ManualResetEventSlim UNBLOCK_MAIN_THREAD = new(false);

    private static WindowsService? service;

    public static void Main(string[] args) {
        service = new WindowsService();
        if (isBackgroundService) {
            ServiceBase.Run(service);
        } else {
            Console.CancelKeyPress += (_, eventArgs) => {
                eventArgs.Cancel = true;
                stop();
            };

            service.startManually(args);

            UNBLOCK_MAIN_THREAD.Wait(); //block while service runs, then exit once user hits Ctrl+C

            service.Dispose();
        }
    }

    public static void stop() {
        if (isBackgroundService) {
            service?.Stop();
        } else {
            service?.stopManually();
            UNBLOCK_MAIN_THREAD.Set();
        }
    }

    private static bool isBackgroundService => !Environment.UserInteractive;

}