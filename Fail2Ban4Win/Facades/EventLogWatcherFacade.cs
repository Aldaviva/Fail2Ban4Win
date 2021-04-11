using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;

#nullable enable

// ReSharper disable InconsistentNaming

namespace Fail2Ban4Win.Facades {

    public interface EventLogWatcherFacade: IDisposable {

        event EventHandler<EventRecordWrittenEventArgsFacade> EventRecordWritten;

        bool Enabled { get; set; }

    }

    internal class EventLogWatcherFacadeImpl: EventLogWatcherFacade {

        private readonly EventLogWatcher watcher;

        public event EventHandler<EventRecordWrittenEventArgsFacade>? EventRecordWritten;

        public bool Enabled {
            get => watcher.Enabled;
            set => watcher.Enabled = value;
        }

        public EventLogWatcherFacadeImpl(EventLogWatcher watcher) {
            this.watcher               =  watcher;
            watcher.EventRecordWritten += WatcherOnEventRecordWritten;
        }

        public EventLogWatcherFacadeImpl(EventLogQueryFacade eventQuery): this(new EventLogWatcher(eventQuery)) { }

        public EventLogWatcherFacadeImpl(EventLogQueryFacade eventQuery, EventBookmark bookmark): this(new EventLogWatcher(eventQuery, bookmark)) { }

        public EventLogWatcherFacadeImpl(EventLogQueryFacade eventQuery, EventBookmark bookmark, bool readExistingEvents): this(new EventLogWatcher(eventQuery, bookmark, readExistingEvents)) { }

        private void WatcherOnEventRecordWritten(object sender, EventRecordWrittenEventArgs e) {
            EventRecordWritten?.Invoke(sender, new EventRecordWrittenEventArgsFacade(e));
        }

        public void Dispose() {
            watcher.EventRecordWritten -= WatcherOnEventRecordWritten;
            watcher.Dispose();
        }

    }

    public class EventLogQueryFacade: EventLogQuery {

        public string path { get; }
        public PathType pathType { get; }
        public string? query { get; }

        public EventLogQueryFacade(string path, PathType pathType): base(path, pathType) {
            this.path     = path;
            this.pathType = pathType;
        }

        public EventLogQueryFacade(string path, PathType pathType, string query): base(path, pathType, query) {
            this.path     = path;
            this.pathType = pathType;
            this.query    = query;
        }

    }

    public class EventRecordWrittenEventArgsFacade {

        public EventLogRecordFacade? EventRecord { get; }
        public Exception? EventException { get; }

        public EventRecordWrittenEventArgsFacade(EventLogRecordFacade eventRecord) {
            EventRecord = eventRecord;
        }

        public EventRecordWrittenEventArgsFacade(Exception eventException) {
            EventException = eventException;
        }

        public EventRecordWrittenEventArgsFacade(EventRecordWrittenEventArgs inner) {
            if (inner.EventRecord is EventLogRecord record) {
                EventRecord = new EventLogRecordFacadeImpl(record);
            }

            EventException = inner.EventException;
        }

    }

    public interface EventLogRecordFacade {

        string LogName { get; }
        int Id { get; }
        string ProviderName { get; }
        IList<EventPropertyFacade> Properties { get; }

        IList<object> GetPropertyValues(EventLogPropertySelectorFacade propertySelector);

    }

    public class EventLogRecordFacadeImpl: EventLogRecordFacade {

        private readonly EventLogRecord record;

        public string LogName => record.LogName;
        public int Id => record.Id;
        public string ProviderName => record.ProviderName;

        public EventLogRecordFacadeImpl(EventLogRecord record) {
            this.record = record;
        }

        public IList<object> GetPropertyValues(EventLogPropertySelectorFacade propertySelector) {
            return record.GetPropertyValues(propertySelector);
        }

        public IList<EventPropertyFacade> Properties => record.Properties.Select(property => new EventPropertyFacade(property)).ToList();

    }

    public class EventPropertyFacade {

        public object Value { get; }

        public EventPropertyFacade(object value) {
            Value = value;
        }

        public EventPropertyFacade(EventProperty property): this(property.Value) { }

    }

    public class EventLogPropertySelectorFacade: EventLogPropertySelector {

        public IEnumerable<string> propertyQueries { get; }

        private EventLogPropertySelectorFacade(ICollection<string> propertyQueries): base(propertyQueries) {
            this.propertyQueries = propertyQueries;
        }

        public EventLogPropertySelectorFacade(IEnumerable<string> propertyQueries): this((ICollection<string>) propertyQueries) { }

    }

}