#nullable enable

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using NLog;

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
    public ICollection<IPNetwork>? neverBanSubnets { get; set; }
    public ICollection<EventLogSelector> eventLogSelectors { get; set; } = null!;

    public override string ToString() =>
        $"{nameof(maxAllowedFailures)}: {maxAllowedFailures}, {nameof(failureWindow)}: {failureWindow}, {nameof(banPeriod)}: {banPeriod}, {nameof(banSubnetBits)}: {banSubnetBits}, {nameof(banRepeatedOffenseCoefficient)}: {banRepeatedOffenseCoefficient}, {nameof(banRepeatedOffenseMax)}: {banRepeatedOffenseMax}, {nameof(neverBanSubnets)}: [{{{string.Join("}, {", neverBanSubnets ?? new IPNetwork[0])}}}], {nameof(eventLogSelectors)}: [{{{string.Join("}, {", eventLogSelectors)}}}], {nameof(isDryRun)}: {isDryRun}, {nameof(logLevel)}: {logLevel}";

    public object Clone() => new Configuration {
        isDryRun                      = isDryRun,
        maxAllowedFailures            = maxAllowedFailures,
        failureWindow                 = failureWindow,
        banPeriod                     = banPeriod,
        banSubnetBits                 = banSubnetBits,
        banRepeatedOffenseCoefficient = banRepeatedOffenseCoefficient,
        banRepeatedOffenseMax         = banRepeatedOffenseMax,
        logLevel                      = logLevel,
        neverBanSubnets               = neverBanSubnets is not null ? new List<IPNetwork>(neverBanSubnets) : null,
        eventLogSelectors             = eventLogSelectors.Select(selector => (EventLogSelector) selector.Clone()).ToList()
    };

}

public class EventLogSelector: ICloneable {

    public string logName { get; set; } = null!;
    public string? source { get; set; }
    public int eventId { get; set; }
    public Regex? ipAddressPattern { get; set; }
    public string? ipAddressEventDataName { get; set; }
    public int ipAddressEventDataIndex { get; set; }

    public override string ToString() =>
        $"{nameof(logName)}: {logName}, {nameof(source)}: {source}, {nameof(eventId)}: {eventId}, {nameof(ipAddressPattern)}: {ipAddressPattern}, {nameof(ipAddressEventDataName)}: {ipAddressEventDataName}, {nameof(ipAddressEventDataIndex)}: {ipAddressEventDataIndex}";

    public object Clone() => new EventLogSelector {
        ipAddressEventDataName  = ipAddressEventDataName,
        eventId                 = eventId,
        ipAddressPattern        = ipAddressPattern is not null ? new Regex(ipAddressPattern.ToString(), ipAddressPattern.Options, ipAddressPattern.MatchTimeout) : null,
        logName                 = logName,
        source                  = source,
        ipAddressEventDataIndex = ipAddressEventDataIndex
    };

}