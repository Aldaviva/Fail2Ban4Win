using System;
using System.ServiceProcess;
using System.Threading;

#nullable enable

namespace Fail2Ban4Win.Entry {

    public static class MainClass {

        private static readonly ManualResetEvent UNBLOCK_MAIN_THREAD = new(false);
        private static readonly WindowsService   SERVICE             = new();

        public static void Main(string[] args) {
            if (Environment.UserInteractive) {
                Console.CancelKeyPress += (_, eventArgs) => {
                    eventArgs.Cancel = true;
                    stop();
                };

                SERVICE.start(args);

                UNBLOCK_MAIN_THREAD.WaitOne(); //block while service runs, then exit once user hits Ctrl+C

                SERVICE.Dispose();
            } else {
                ServiceBase.Run(SERVICE);
            }
        }

        public static void stop() {
            SERVICE.stop();
            UNBLOCK_MAIN_THREAD.Set();
        }

    }

}