#nullable enable

using Fail2Ban4Win.Plugins;
using Fail2Ban4Win.Services;
using LightInject;
using Plugins;

namespace Fail2Ban4Win.Injection;

public class ServiceModules: ICompositionRoot {

    public void Compose(IServiceRegistry serviceRegistry) {
        serviceRegistry.Register<BanManager, BanManagerImpl>(new PerScopeLifetime());
        serviceRegistry.Register<EventLogListener, EventLogListenerImpl>(new PerScopeLifetime());
        serviceRegistry.Register<IPluginManager<IFail2Ban4WinPlugin>>(_ => {
            var pluginManager = new PluginManager<IFail2Ban4WinPlugin>("plugins");
            pluginManager.LoadAll();
            return pluginManager;
        }, new PerScopeLifetime());
    }

}