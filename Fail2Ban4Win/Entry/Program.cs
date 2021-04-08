using System;
using System.ServiceProcess;
using System.Threading;

#nullable enable

namespace Fail2Ban4Win.Entry {

    internal static class Program {

        private static void Main(string[] args) {
            WindowsService service = new();

            if (Environment.UserInteractive) {
                ManualResetEvent unblockMainThread = new(false);

                Console.CancelKeyPress += (_, eventArgs) => {
                    eventArgs.Cancel = true;
                    service.stop();
                    unblockMainThread.Set();
                };

                service.start(args);

                unblockMainThread.WaitOne(); //block while service runs, then exit once user hits Ctrl+C
            } else {
                ServiceBase.Run(service);
            }
        }

    }

}