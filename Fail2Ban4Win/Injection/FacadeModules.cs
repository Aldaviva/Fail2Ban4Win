#nullable enable

using Fail2Ban4Win.Facades;
using LightInject;

namespace Fail2Ban4Win.Injection; 

public class FacadeModules: ICompositionRoot {

    public void Compose(IServiceRegistry serviceRegistry) {
        serviceRegistry.Register<FirewallFacade, FirewallWASFacade>(new PerContainerLifetime());

        serviceRegistry.Register<EventLogQueryFacade, EventLogWatcherFacade>((_, query) => new EventLogWatcherFacadeImpl(query));
    }

}