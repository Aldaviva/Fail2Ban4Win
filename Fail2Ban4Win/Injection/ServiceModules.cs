﻿#nullable enable

using Fail2Ban4Win.Services;
using LightInject;

namespace Fail2Ban4Win.Injection; 

public class ServiceModules: ICompositionRoot {

    public void Compose(IServiceRegistry serviceRegistry) {
        serviceRegistry.Register<BanManager, BanManagerImpl>(new PerScopeLifetime());
        serviceRegistry.Register<EventLogListener, EventLogListenerImpl>(new PerScopeLifetime());
    }

}