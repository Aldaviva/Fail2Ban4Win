﻿#nullable enable

using Fail2Ban4Win.Config;
using LightInject;
using Microsoft.Extensions.Configuration;

namespace Fail2Ban4Win.Injection; 

public class ConfigurationModule: ICompositionRoot {

    internal const string CONFIGURATION_FILENAME = "configuration.json";

    public void Compose(IServiceRegistry serviceRegistry) {
        serviceRegistry.Register(_ => new ConfigurationBuilder().AddJsonFile(CONFIGURATION_FILENAME).Build().Get<Configuration>(), new PerScopeLifetime());

        IPNetworkDeserializer.register();
        RegexDeserializer.register();
    }

}