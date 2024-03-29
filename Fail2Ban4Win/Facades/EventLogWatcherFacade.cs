﻿#nullable enable

using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;

// ReSharper disable InconsistentNaming

namespace Fail2Ban4Win.Facades;

public interface EventLogWatcherFacade: IDisposable {

    event EventHandler<EventRecordWrittenEventArgsFacade> EventRecordWritten;

    bool Enabled { get; set; }

}

public class EventLogWatcherFacadeImpl: EventLogWatcherFacade {

    private readonly EventLogWatcher watcher;

    public event EventHandler<EventRecordWrittenEventArgsFacade>? EventRecordWritten;

    /// <summary>Determines whether this object starts delivering events to the event delegate.</summary>
    /// <returns>Returns <see langword="true" /> when this object can deliver events to the event delegate, and returns <see langword="false" /> when this object has stopped delivery.</returns>
    /// <exception cref="EventLogNotFoundException">If the <c>EventLogQueryFacade.path</c> cannot be found while setting <c>Enabled</c> to <see langword="true" />.</exception>
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

    /// <summary>
    /// The EventRecord being notified.
    /// NOTE: If non null, then caller is required to call Dispose().
    /// </summary>
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

public interface EventLogRecordFacade: IDisposable {

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

    public void Dispose() {
        record.Dispose();
    }

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