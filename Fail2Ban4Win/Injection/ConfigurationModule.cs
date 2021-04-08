using Fail2Ban4Win.Config;
using LightInject;
using Microsoft.Extensions.Configuration;

#nullable enable

namespace Fail2Ban4Win.Injection {

    public class ConfigurationModule: ICompositionRoot {

        private const string CONFIGURATION_FILENAME = "configuration.json";

        public void Compose(IServiceRegistry serviceRegistry) {
            serviceRegistry.Register(_ => new ConfigurationBuilder().AddJsonFile(CONFIGURATION_FILENAME).Build().Get<Configuration>(), new PerScopeLifetime());

            IPNetworkConverter.register();
            RegexConverter.register();
        }

    }

}