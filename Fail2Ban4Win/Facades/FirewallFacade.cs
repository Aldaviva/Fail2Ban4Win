using WindowsFirewallHelper;
using WindowsFirewallHelper.Collections;
using WindowsFirewallHelper.FirewallRules;

#nullable enable

// ReSharper disable InconsistentNaming

namespace Fail2Ban4Win.Facades {

    public interface FirewallFacade {

        IFirewallWASRulesCollection<FirewallWASRule> Rules { get; }

    }

    internal class FirewallWASFacade: FirewallFacade {

        private readonly FirewallWAS instance;

        public FirewallWASFacade(): this(FirewallWAS.Instance) { }

        public FirewallWASFacade(FirewallWAS instance) {
            this.instance = instance;
        }

        public IFirewallWASRulesCollection<FirewallWASRule> Rules => instance.Rules;

    }

}