#nullable enable

using Fail2Ban4Win.Config;
using Fail2Ban4Win.Data;
using Fail2Ban4Win.Facades;
using NLog;
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Net;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;

namespace Fail2Ban4Win.Services;

public interface EventLogListener: IDisposable {

    public event EventHandler<IPAddress> failure;

}

public class EventLogListenerImpl: EventLogListener {

    private static readonly Logger LOGGER = LogManager.GetLogger(nameof(EventLogListenerImpl));

    private static readonly Regex DEFAULT_IPV4_ADDRESS_PATTERN = new(@"(?<ipAddress>\b(?:(?:(?:25[0-5])|(?:2[0-4]\d)|(?:[01]?\d{1,2}))\.){3}(?:(?:25[0-5])|(?:2[0-4]\d)|(?:[01]?\d{1,2}))\b)",
        RegexOptions.None, RegexDeserializer.MATCH_TIMEOUT);

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
                using EventLogRecordFacade? record = args.EventRecord;
                if (record != null) {
                    onEventRecordWritten(record, selector);
                }
            };

            try {
                watcher.Enabled = true;
            } catch (EventLogNotFoundException e) {
                LOGGER.Warn("Failed to listen for events in log {0}: {1}. Skipping this event selector", selector.logName, e.Message);
                watcher.Dispose();
                return null;
            } catch (UnauthorizedAccessException e) {
                LOGGER.Warn("Failed to listen for events in log {0}, possibly because the log does not exist and this program is not running elevated. Skipping this event selector. {1}",
                    selector.logName, e.Message);
                watcher.Dispose();
                return null;
            }

            LOGGER.Info("Listening for Event Log records from the {0} log with event ID {1} and {2}", selector.logName, selector.eventId,
                selector.source is not null ? "source " + selector.source : "any source");
            return watcher;
        }).Compact().ToList();
    }

    private void onEventRecordWritten(EventLogRecordFacade record, EventLogSelector selector) {
        LOGGER.Trace("Received Event Log record from log {0} with event ID {1} and source {2}", record.LogName, record.Id, record.ProviderName);

        string? stringContainingIpAddress = selector.ipAddressEventDataName is null
            ? record.Properties.ElementAtOrDefault(selector.ipAddressEventDataIndex)?.Value as string
            : record.GetPropertyValues(new EventLogPropertySelectorFacade([$"Event/EventData/Data[@Name=\"{SecurityElement.Escape(selector.ipAddressEventDataName)}\"]"]))
                .ElementAtOrDefault(selector.ipAddressEventDataIndex) as string;

        if (stringContainingIpAddress is not null) {
            LOGGER.Trace("Searching for IPv4 address in {0}", stringContainingIpAddress);
            try {
                MatchCollection matchCollection = (selector.ipAddressPattern ?? DEFAULT_IPV4_ADDRESS_PATTERN).Matches(stringContainingIpAddress);

                if (matchCollection.Count > 0) {
                    IEnumerable<IPAddress> failingIpAddresses = matchCollection.Cast<Match>().Select(match => IPAddress.Parse(match.Groups["ipAddress"].Value));

                    foreach (IPAddress failingIpAddress in failingIpAddresses) {
                        LOGGER.Info("Authentication failure detected from {0} (log={1}, event={2}, source={3})", failingIpAddress, record.LogName, record.Id, record.ProviderName);
                        failure?.Invoke(this, failingIpAddress);
                    }
                }
            } catch (RegexMatchTimeoutException) {
                LOGGER.Warn("Searching for IP address in event {0} with ID {1} from {2} source of {3} log took more than {4:g}, ignoring this event.",
                    record.RecordId, record.Id, record.ProviderName, record.LogName, RegexDeserializer.MATCH_TIMEOUT);
            }
        }
    }

    /// <summary>https://docs.microsoft.com/en-us/previous-versions/bb399427(v=vs.90)</summary>
    private static string selectorToQuery(EventLogSelector selector) {
        StringBuilder queryBuilder = new("*");
        queryBuilder.Append($"[System/EventID={selector.eventId}]");

        if (!string.IsNullOrWhiteSpace(selector.source)) {
            queryBuilder.Append($"[System/Provider/@Name=\"{SecurityElement.Escape(selector.source)}\"]");
        }

        if (!string.IsNullOrWhiteSpace(selector.eventPredicate)) {
            queryBuilder.Append(selector.eventPredicate);
        }

        return queryBuilder.ToString();
    }

    public void Dispose() {
        foreach (EventLogWatcherFacade watcher in watchers) {
            watcher.Dispose();
        }
    }

}