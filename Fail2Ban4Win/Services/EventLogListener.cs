using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Net;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;
using Fail2Ban4Win.Config;
using Fail2Ban4Win.Facades;
using NLog;

#nullable enable

namespace Fail2Ban4Win.Services {

    public interface EventLogListener: IDisposable {

        public event EventHandler<IPAddress> failure;

    }

    public class EventLogListenerImpl: EventLogListener {

        private static readonly Logger LOGGER = LogManager.GetLogger(nameof(EventLogListenerImpl));

        private static readonly Regex DEFAULT_IPV4_ADDRESS_PATTERN = new(@"(?<ipAddress>\b(?:(?:(?:25[0-5])|(?:2[0-4]\d)|(?:[01]?\d{1,2}))\.){3}(?:(?:25[0-5])|(?:2[0-4]\d)|(?:[01]?\d{1,2}))\b)");

        public event EventHandler<IPAddress>? failure;

        private readonly IEnumerable<EventLogWatcherFacade> watchers;

        public EventLogListenerImpl(Configuration configuration, Func<EventLogQueryFacade, EventLogWatcherFacade> eventLogWatcherFacadeFactory) {
            watchers = configuration.eventLogSelectors.Select(selector => {
                if (!selector.ipAddressPattern?.GetGroupNames().Contains("ipAddress") ?? false) {
                    throw new ArgumentException($"Event log selector for event {selector.eventId} in log {selector.logName} contains an ipAddressPattern ({selector.ipAddressPattern}), " +
                        "but the pattern does not contain a named capturing group with the name \"ipAddress\"." +
                        "Ensure the pattern contains a group that looks like \"(?<ipAddress>(?:\\d{{1,3}}\\.){{3}}\\d{{1,3}})\" or similar.");
                }

                EventLogWatcherFacade watcher = eventLogWatcherFacadeFactory(new EventLogQueryFacade(selector.logName, PathType.LogName, selectorToQuery(selector)));
                watcher.EventRecordWritten += (_, args) => {
                    if (args.EventRecord is { } record) {
                        onEventRecordWritten(record, selector);
                    }
                };
                watcher.Enabled = true;
                LOGGER.Info("Listening for Event Log records from the {0} log with event ID {1} and {2}.", selector.logName, selector.eventId,
                    selector.source is not null ? "source " + selector.source : "any source");
                return watcher;
            }).ToList();
        }

        private void onEventRecordWritten(EventLogRecordFacade record, EventLogSelector selector) {
            LOGGER.Trace("Received Event Log record from log {0} with event ID {1} and source {2}", record.LogName, record.Id, record.ProviderName);

            string? stringContainingIpAddress = selector.ipAddressEventDataName is null
                ? record.Properties.FirstOrDefault()?.Value as string
                : record.GetPropertyValues(new EventLogPropertySelectorFacade(new[] { $"Event/EventData/Data[@Name=\"{SecurityElement.Escape(selector.ipAddressEventDataName)}\"]" }))
                    .FirstOrDefault() as string;

            if (stringContainingIpAddress is not null) {
                LOGGER.Trace("Searching for IPv4 address in {0}", stringContainingIpAddress);

                MatchCollection matchCollection = (selector.ipAddressPattern ?? DEFAULT_IPV4_ADDRESS_PATTERN).Matches(stringContainingIpAddress);

                if (matchCollection.Count > 0) {
                    IEnumerable<IPAddress> failingIpAddresses = matchCollection.Cast<Match>().Select(match => IPAddress.Parse(match.Groups["ipAddress"].Value));

                    foreach (IPAddress failingIpAddress in failingIpAddresses) {
                        LOGGER.Info("Authentication failure detected from {0} (log={1}, event={2}, source={3}).", failingIpAddress, record.LogName, record.Id, record.ProviderName);
                        failure?.Invoke(this, failingIpAddress);
                    }
                } else {
                    LOGGER.Trace("Could not find any IPv4 addresses in {0}", stringContainingIpAddress);
                }
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
            foreach (EventLogWatcherFacade watcher in watchers) {
                watcher.Dispose();
            }
        }

    }

}