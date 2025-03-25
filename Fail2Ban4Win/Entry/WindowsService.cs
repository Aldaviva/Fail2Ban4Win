#nullable enable

using Fail2Ban4Win.Services;
using LightInject;
using System.Reflection;
using System.ServiceProcess;

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

        scope.GetInstance<BanManager>();
    }

    protected override void OnStop() {
        scope?.Dispose();
        context?.Dispose();
    }

    public void stopManually() {
        OnStop();
    }

    public void startManually(string[] args) {
        OnStart(args);
    }

}