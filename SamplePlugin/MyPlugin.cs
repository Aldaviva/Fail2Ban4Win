using Fail2Ban4Win.Data;

namespace Fail2Ban4Win.Plugins.SamplePlugin;

public class MyPlugin: IFail2Ban4WinPlugin, IDisposable {

    public MyPlugin() {
        // optional initialization logic when Fail2Ban4Win launches
    }

    public void OnAuthFailureDetected(FailureParams failure) {
        // logic when an IP address fails to authenticate once
    }

    public void OnSubnetBanned(BanParams ban) {
        // logic when a subnet failed enough times to get banned in the firewall
    }

    public void OnBanLifted(BanParams ban) {
        // logic when a subnet was banned long enough for the ban to expire and be deleted from the firewall
    }

    public void Dispose() {
        // optional cleanup logic when Fail2Ban4Win exits
    }

}