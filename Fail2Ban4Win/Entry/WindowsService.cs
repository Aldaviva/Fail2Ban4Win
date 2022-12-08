#nullable enable

using System.Reflection;
using System.ServiceProcess;
using Fail2Ban4Win.Services;
using LightInject;
using NLog;
using NLog.Config;

namespace Fail2Ban4Win.Entry; 

public partial class WindowsService: ServiceBase {

    private ServiceContainer? context;
    private Scope?            scope;

    public WindowsService() {
        InitializeComponent();
    }

    protected override void OnStart(string[] args) {
        context = new ServiceContainer();
        context.RegisterAssembly(Assembly.GetCallingAssembly());
        scope = context.BeginScope();

        LogManager.Configuration = scope.GetInstance<LoggingConfiguration>();
        scope.GetInstance<BanManager>();
    }

    protected override void OnStop() {
        scope?.Dispose();
        context?.Dispose();
    }

    public void stop() {
        OnStop();
    }

    public void start(string[] args) {
        OnStart(args);
    }

}