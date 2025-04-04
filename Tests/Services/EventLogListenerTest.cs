﻿#nullable enable

using Fail2Ban4Win.Config;
using Fail2Ban4Win.Facades;
using Fail2Ban4Win.Services;
using FakeItEasy;
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using Tests.Logging;
using Xunit;
using Xunit.Abstractions;

namespace Tests.Services;

public class EventLogListenerTest: IDisposable {

    private readonly Configuration configuration = new() {
        isDryRun           = false,
        failureWindow      = TimeSpan.FromSeconds(2),
        banPeriod          = TimeSpan.FromSeconds(5),
        banSubnetBits      = 8,
        maxAllowedFailures = 2,
        neverBanSubnets    = [IPNetwork2.Parse("73.202.12.148/32")],
        eventLogSelectors = [
            new EventLogSelector {
                logName                = "Security",
                eventId                = 4625,
                ipAddressEventDataName = "IpAddress"
            },
            new EventLogSelector {
                logName          = "Application",
                source           = "sshd",
                eventId          = 0,
                ipAddressPattern = new Regex(@"^sshd: PID \d+: Failed password for(?: invalid user)? \S+ from (?<ipAddress>(?:\d{1,3}\.){3}\d{1,3}) port \d+ ssh\d?$")
            },
            new EventLogSelector {
                logName                 = "Application",
                source                  = "MSExchangeFrontEndTransport",
                eventId                 = 1035,
                ipAddressEventDataIndex = 3
            },
            new EventLogSelector {
                logName                = "Microsoft-Windows-IIS-Logging/Logs",
                source                 = "IIS-Logging",
                eventId                = 6200,
                ipAddressEventDataName = "c-ip",
                eventPredicate         = "[EventData/Data[@Name='sc-status']=403]"
            }
        ]
    };

    private readonly EventLogListener listener;

    private readonly IList<EventLogWatcherFacade> watcherFacades = [];
    private readonly IList<EventLogQueryFacade>   queries        = [];

    public EventLogListenerTest(ITestOutputHelper testOutputHelper) {
        XunitTestOutputTarget.start(testOutputHelper);

        listener = new EventLogListenerImpl(configuration, createEventLogWatcherFacade);
    }

    private EventLogWatcherFacade createEventLogWatcherFacade(EventLogQueryFacade eventQuery) {
        queries.Add(eventQuery);
        EventLogWatcherFacade watcherFacade = A.Fake<EventLogWatcherFacade>();
        watcherFacades.Add(watcherFacade);
        return watcherFacade;
    }

    public void Dispose() {
        listener.Dispose();
    }

    [Fact]
    public void queryWithoutSource() {
        EventLogQueryFacade actual = queries[0];
        Assert.Equal("Security", actual.path);
        Assert.Equal(PathType.LogName, actual.pathType);
        Assert.Equal("*[System/EventID=4625]", actual.query);
    }

    [Fact]
    public void queryWithSource() {
        EventLogQueryFacade actual = queries[1];
        Assert.Equal("Application", actual.path);
        Assert.Equal(PathType.LogName, actual.pathType);
        Assert.Equal("*[System/EventID=0][System/Provider/@Name=\"sshd\"]", actual.query);
    }

    [Fact]
    public void queryWithSourceAndPredicate() {
        EventLogQueryFacade actual = queries[3];
        Assert.Equal("Microsoft-Windows-IIS-Logging/Logs", actual.path);
        Assert.Equal(PathType.LogName, actual.pathType);
        Assert.Equal("*[System/EventID=6200][System/Provider/@Name=\"IIS-Logging\"][EventData/Data[@Name='sc-status']=403]", actual.query);
    }

    [Fact]
    public void builtInPattern() {
        EventLogRecordFacade record = A.Fake<EventLogRecordFacade>();
        A.CallTo(() => record.GetPropertyValues(A<EventLogPropertySelectorFacade>._)).Returns(["141.98.9.20"]);
        IPAddress? actualAddress = null;
        listener.failure += (_, address) => actualAddress = address;

        watcherFacades[0].EventRecordWritten += Raise.With(null, new EventRecordWrittenEventArgsFacade(record));

        A.CallTo(() => record.GetPropertyValues(A<EventLogPropertySelectorFacade>.That.Matches(selector =>
            selector.propertyQueries.SequenceEqual(new[] { "Event/EventData/Data[@Name=\"IpAddress\"]" })))).MustHaveHappened();
        A.CallTo(() => record.Properties).MustNotHaveHappened();

        Assert.Equal(IPAddress.Parse("141.98.9.20"), actualAddress);
    }

    [Fact]
    public void customPattern() {
        EventLogRecordFacade record = A.Fake<EventLogRecordFacade>();
        A.CallTo(() => record.Properties)
            .Returns([new EventPropertyFacade("sshd: PID 29722: Failed password for invalid user root from 71.194.180.25 port 48316 ssh2")]);
        IPAddress? actualAddress = null;
        listener.failure += (_, address) => actualAddress = address;

        watcherFacades[1].EventRecordWritten += Raise.With(null, new EventRecordWrittenEventArgsFacade(record));

        A.CallTo(() => record.Properties).MustHaveHappened();
        A.CallTo(() => record.GetPropertyValues(A<EventLogPropertySelectorFacade>._)).MustNotHaveHappened();

        Assert.Equal(IPAddress.Parse("71.194.180.25"), actualAddress);
    }

    [Fact]
    public void logNameNotFoundSkipsSelector() {

        Configuration invalidConfiguration = (Configuration) configuration.Clone();
        invalidConfiguration.eventLogSelectors.Clear();
        invalidConfiguration.eventLogSelectors.Add(new EventLogSelector {
            logName = $"fake event log {Guid.NewGuid()}",
            eventId = 0
        });

        EventLogWatcherFacade watcher = A.Fake<EventLogWatcherFacade>();
        A.CallToSet(() => watcher.Enabled).Throws<EventLogNotFoundException>();

        _ = new EventLogListenerImpl(invalidConfiguration, _ => watcher);

        A.CallTo(() => watcher.Dispose()).MustHaveHappened();
    }

    [Fact]
    public void logPermissionDeniedSkipsSelector() {

        Configuration invalidConfiguration = (Configuration) configuration.Clone();
        invalidConfiguration.eventLogSelectors.Clear();
        invalidConfiguration.eventLogSelectors.Add(new EventLogSelector {
            logName = $"fake event log {Guid.NewGuid()}",
            eventId = 0
        });

        EventLogWatcherFacade watcher = A.Fake<EventLogWatcherFacade>();
        A.CallToSet(() => watcher.Enabled).Throws<UnauthorizedAccessException>();

        _ = new EventLogListenerImpl(invalidConfiguration, _ => watcher);

        A.CallTo(() => watcher.Dispose()).MustHaveHappened();
    }

    [Fact]
    public void missingPatternGroupThrowsException() {
        Configuration invalidConfiguration = (Configuration) configuration.Clone();
        invalidConfiguration.eventLogSelectors.Clear();
        invalidConfiguration.eventLogSelectors.Add(new EventLogSelector {
            logName          = "Application",
            eventId          = 0,
            ipAddressPattern = new Regex("hello")
        });

        Assert.Throws<ArgumentException>(() => new EventLogListenerImpl(invalidConfiguration, query => new EventLogWatcherFacadeImpl(query)));
    }

    [Fact]
    public void eventDataIndex() {
        EventLogRecordFacade record = A.Fake<EventLogRecordFacade>();
        A.CallTo(() => record.Properties).Returns([
            new EventPropertyFacade("LogonDenied"),
            new EventPropertyFacade("Default Frontend WIN-EXCHANGE"),
            new EventPropertyFacade("Login"),
            new EventPropertyFacade("42.85.233.11")
        ]);
        IPAddress? actualAddress = null;
        listener.failure += (_, address) => actualAddress = address;

        watcherFacades[2].EventRecordWritten += Raise.With(null, new EventRecordWrittenEventArgsFacade(record));

        A.CallTo(() => record.Properties).MustHaveHappened();
        A.CallTo(() => record.GetPropertyValues(A<EventLogPropertySelectorFacade>._)).MustNotHaveHappened();

        Assert.Equal(IPAddress.Parse("42.85.233.11"), actualAddress);
    }

}