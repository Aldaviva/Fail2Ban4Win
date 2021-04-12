using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using Fail2Ban4Win.Config;
using Fail2Ban4Win.Facades;
using Fail2Ban4Win.Services;
using FakeItEasy;
using NLog;
using Tests.Logging;
using Xunit;
using Xunit.Abstractions;

#nullable enable

namespace Tests.Services {

    public class EventLogListenerTest: IDisposable {

        private readonly Configuration configuration = new() {
            isDryRun           = false,
            failureWindow      = TimeSpan.FromSeconds(2),
            banPeriod          = TimeSpan.FromSeconds(5),
            banSubnetBits      = 8,
            logLevel           = LogLevel.Trace,
            maxAllowedFailures = 2,
            neverBanSubnets    = new[] { IPNetwork.Parse("73.202.12.148/32") },
            eventLogSelectors = new[] {
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
                }
            }
        };

        private readonly EventLogListener listener;

        private readonly IList<EventLogWatcherFacade> watcherFacades = new List<EventLogWatcherFacade>();
        private readonly IList<EventLogQueryFacade>   queries        = new List<EventLogQueryFacade>();

        public EventLogListenerTest(ITestOutputHelper testOutputHelper) {
            XunitTestOutputTarget.start(testOutputHelper);

            listener = new EventLogListenerImpl(configuration, createEventLogWatcherFacade);
        }

        private EventLogWatcherFacade createEventLogWatcherFacade(EventLogQueryFacade eventQuery) {
            queries.Add(eventQuery);
            var watcherFacade = A.Fake<EventLogWatcherFacade>();
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
        public void builtInPattern() {
            EventLogRecordFacade record = A.Fake<EventLogRecordFacade>();
            A.CallTo(() => record.GetPropertyValues(A<EventLogPropertySelectorFacade>._)).Returns(new object[] { "141.98.9.20" });
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
                .Returns(new List<EventPropertyFacade> { new("sshd: PID 29722: Failed password for invalid user root from 71.194.180.25 port 48316 ssh2") });
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

            var watcher = A.Fake<EventLogWatcherFacade>();
            A.CallToSet(() => watcher.Enabled).Throws<EventLogNotFoundException>();

            new EventLogListenerImpl(invalidConfiguration, _ => watcher);

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

    }

}