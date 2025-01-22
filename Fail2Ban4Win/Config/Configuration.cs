#nullable enable

using NLog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;

namespace Fail2Ban4Win.Config;

public class Configuration: ICloneable {

    public bool isDryRun { get; set; }
    public int maxAllowedFailures { get; set; }
    public TimeSpan failureWindow { get; set; }
    public TimeSpan banPeriod { get; set; }
    public byte? banSubnetBits { get; set; }
    public double? banRepeatedOffenseCoefficient { get; set; }
    public int? banRepeatedOffenseMax { get; set; }
    public LogLevel? logLevel { get; set; }
    public ICollection<IPNetwork2>? neverBanSubnets { get; set; }
    public bool neverBanReservedSubnets { get; set; } = true;
    public ICollection<EventLogSelector> eventLogSelectors { get; set; } = null!;
    public string? logFolder { get; set; } // absolute or relative to executable
    public int? logHistory { get; set; } // number of logs to archive ... default is 100, log archiving is done daily

    public override string ToString() =>
        $"{nameof(maxAllowedFailures)}: {maxAllowedFailures}, {nameof(failureWindow)}: {failureWindow}, {nameof(banPeriod)}: {banPeriod}, {nameof(banSubnetBits)}: {banSubnetBits}, {nameof(banRepeatedOffenseCoefficient)}: {banRepeatedOffenseCoefficient}, {nameof(banRepeatedOffenseMax)}: {banRepeatedOffenseMax}, {nameof(neverBanSubnets)}: [{{{string.Join("}, {", neverBanSubnets ?? Array.Empty<IPNetwork2>())}}}], {nameof(eventLogSelectors)}: [{{{string.Join("}, {", eventLogSelectors)}}}], {nameof(isDryRun)}: {isDryRun}, {nameof(logLevel)}: {logLevel}";

    public object Clone() => new Configuration {
        isDryRun                      = isDryRun,
        maxAllowedFailures            = maxAllowedFailures,
        failureWindow                 = failureWindow,
        banPeriod                     = banPeriod,
        banSubnetBits                 = banSubnetBits,
        banRepeatedOffenseCoefficient = banRepeatedOffenseCoefficient,
        banRepeatedOffenseMax         = banRepeatedOffenseMax,
        logLevel                      = logLevel,
        neverBanSubnets               = neverBanSubnets is not null ? new List<IPNetwork2>(neverBanSubnets) : null,
        eventLogSelectors             = eventLogSelectors.Select(selector => (EventLogSelector) selector.Clone()).ToList(),
        logFolder                     = logFolder,
        logHistory                    = logHistory,
    };

}

public class EventLogSelector: ICloneable {

    public string logName { get; set; } = null!;
    public string? source { get; set; }
    public int eventId { get; set; }
    public Regex? ipAddressPattern { get; set; }
    public string? ipAddressEventDataName { get; set; }
    public int ipAddressEventDataIndex { get; set; }
    public string? eventPredicate { get; set; }

    public override string ToString() =>
        $"{nameof(logName)}: {logName}, {nameof(source)}: {source}, {nameof(eventId)}: {eventId}, {nameof(ipAddressPattern)}: {ipAddressPattern}, {nameof(ipAddressEventDataName)}: {ipAddressEventDataName}, {nameof(ipAddressEventDataIndex)}: {ipAddressEventDataIndex}, {nameof(eventPredicate)}: {eventPredicate}";

    public object Clone() => new EventLogSelector {
        ipAddressEventDataName  = ipAddressEventDataName,
        eventId                 = eventId,
        ipAddressPattern        = ipAddressPattern is not null ? new Regex(ipAddressPattern.ToString(), ipAddressPattern.Options, ipAddressPattern.MatchTimeout) : null,
        logName                 = logName,
        source                  = source,
        ipAddressEventDataIndex = ipAddressEventDataIndex,
        eventPredicate          = eventPredicate
    };

}