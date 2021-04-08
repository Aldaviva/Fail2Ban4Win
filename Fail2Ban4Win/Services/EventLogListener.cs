using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Net;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;
using Fail2Ban4Win.Config;

#nullable enable

namespace Fail2Ban4Win.Services {

    public interface EventLogListener: IDisposable {

        public event EventHandler<IPAddress> failure;

    }

    public class EventLogListenerImpl: EventLogListener {

        private static readonly Regex DEFAULT_IPV4_ADDRESS_PATTERN = new(@"(?<ipAddress>\b(?:(?:(?:25[0-5])|(?:2[0-4]\d)|(?:[01]?\d{1,2}))\.){3}(?:(?:25[0-5])|(?:2[0-4]\d)|(?:[01]?\d{1,2}))\b)");

        public event EventHandler<IPAddress>? failure;

        private readonly IEnumerable<EventLogWatcher> watchers;

        public EventLogListenerImpl(Configuration configuration) {
            watchers = configuration.eventLogSelectors.Select(selector => {
                if (!selector.ipAddressPattern?.GetGroupNames().Contains("ipAddress") ?? false) {
                    throw new ArgumentException($"Event log selector for event {selector.eventId} in log {selector.logName} contains an ipAddressPattern ({selector.ipAddressPattern}), " +
                        "but the pattern does not contain a named capturing group with the name \"ipAddress\"." +
                        "Ensure the pattern contains a group that looks like \"(?<ipAddress>(?:\\d{{1,3}}\\.){{3}}\\d{{1,3}})\" or similar.");
                }

                var watcher = new EventLogWatcher(new EventLogQuery(selector.logName, PathType.LogName, selectorToQuery(selector)));
                watcher.EventRecordWritten += (_, args) => {
                    if (args.EventRecord is EventLogRecord record) {
                        onEventRecordWritten(record, selector);
                    }
                };
                watcher.Enabled = true;
                return watcher;
            }).ToList();
        }

        private void onEventRecordWritten(EventLogRecord record, EventLogSelector selector) {
            string propertySelector = selector.ipAddressEventDataName is null
                ? "Event/EventData/Data"
                : $"Event/EventData/Data[@Name=\"{SecurityElement.Escape(selector.ipAddressEventDataName)}\"]";
            string stringContainingIpAddress = Convert.ToString(record.GetPropertyValues(new EventLogPropertySelector(new[] { propertySelector }))[0]);

            MatchCollection        matchCollection    = (selector.ipAddressPattern ?? DEFAULT_IPV4_ADDRESS_PATTERN).Matches(stringContainingIpAddress);
            IEnumerable<IPAddress> failingIpAddresses = matchCollection.Cast<Match>().Select(match => IPAddress.Parse(match.Groups["ipAddress"].Value));

            foreach (IPAddress failingIpAddress in failingIpAddresses) {
                failure?.Invoke(this, failingIpAddress);
            }
        }

        /// <summary>https://docs.microsoft.com/en-us/previous-versions/bb399427(v=vs.90)</summary>
        private static string selectorToQuery(EventLogSelector selector) {
            StringBuilder queryBuilder = new("*");
            queryBuilder.Append($"[System/EventID={selector.eventId}]");

            if (selector.source is not null) {
                queryBuilder.Append($"[System/Provider/@Name=\"{SecurityElement.Escape(selector.source)}\"]");
            }

            return queryBuilder.ToString();
        }

        public void Dispose() {
            foreach (EventLogWatcher watcher in watchers) {
                watcher.Dispose();
            }
        }

    }

}