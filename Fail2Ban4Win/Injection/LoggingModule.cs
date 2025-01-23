#nullable enable

using Fail2Ban4Win.Config;
using LightInject;
using NLog.Config;
using NLog.Targets;
using System;
using LogLevel = NLog.LogLevel;

namespace Fail2Ban4Win.Injection; 

public class LoggingModule: ICompositionRoot {

    public void Compose(IServiceRegistry serviceRegistry) {
        serviceRegistry.Register(factory => {
            LoggingConfiguration config = new();

            ConsoleTarget console = new() {
                Layout =
                    "${pad:padding=-5:fixedLength=true:inner=${level}} - ${date:yyyy-MM-dd\\THH\\:mm\\:ss.fffzzz} - ${logger:shortName=true} - ${message}${when:when='${exception}' != '':inner=${newline}${exception:format=ToString,StackTrace:separator=\r\n}}"
            };

            Configuration configuration = factory.GetInstance<Configuration>();
            config.AddRule(configuration.logLevel ?? LogLevel.Debug, LogLevel.Fatal, console);
            var logFolder = configuration.logFolder;
            if(!string.IsNullOrEmpty(logFolder)) {
                FileTarget fileTarget = new FileTarget();
                fileTarget.ArchiveEvery = FileArchivePeriod.Day;
                fileTarget.MaxArchiveFiles = configuration.logHistory ?? 100;
                fileTarget.EnableArchiveFileCompression = true;
                fileTarget.FileName = System.IO.Path.Combine(logFolder, "${date:format=yyyy-MM-dd}.log");
                fileTarget.Layout = console.Layout;
                config.AddRule(configuration.logLevel ?? LogLevel.Debug, LogLevel.Fatal, fileTarget);
            }

            // It might be nice to also log to a file or Windows Event Log, since this runs as a headless service with no console output.

            return config;
        }, new PerContainerLifetime());
    }

}