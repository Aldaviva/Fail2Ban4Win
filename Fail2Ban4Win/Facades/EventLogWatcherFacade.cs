#nullable enable

using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;

// ReSharper disable InconsistentNaming

namespace Fail2Ban4Win.Facades;

/// <inheritdoc cref="EventLogWatcher"/>
public interface EventLogWatcherFacade: IDisposable {

    /// <inheritdoc cref="EventLogWatcher.EventRecordWritten"/>
    event EventHandler<EventRecordWrittenEventArgsFacade> EventRecordWritten;

    /// <inheritdoc cref="EventLogWatcher.Enabled"/>
    /// <exception cref="EventLogNotFoundException">if the given event log does not exist</exception>
    /// <exception cref="UnauthorizedAccessException">if the given event log does not exist and this process does not have permissions to create it</exception>
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

    /// <inheritdoc cref="EventLogWatcher(EventLogQuery)"/>
    public EventLogWatcherFacadeImpl(EventLogQueryFacade eventQuery): this(new EventLogWatcher(eventQuery)) { }

    /// <inheritdoc cref="EventLogWatcher(EventLogQuery, EventBookmark)"/>
    public EventLogWatcherFacadeImpl(EventLogQueryFacade eventQuery, EventBookmark bookmark): this(new EventLogWatcher(eventQuery, bookmark)) { }

    /// <inheritdoc cref="EventLogWatcher(EventLogQuery, EventBookmark, bool)"/>
    public EventLogWatcherFacadeImpl(EventLogQueryFacade eventQuery, EventBookmark bookmark, bool readExistingEvents): this(new EventLogWatcher(eventQuery, bookmark, readExistingEvents)) { }

    private void WatcherOnEventRecordWritten(object sender, EventRecordWrittenEventArgs e) {
        EventRecordWritten?.Invoke(sender, new EventRecordWrittenEventArgsFacade(e));
    }

    public void Dispose() {
        watcher.EventRecordWritten -= WatcherOnEventRecordWritten;
        watcher.Dispose();
    }

}

/// <inheritdoc cref="EventLogQuery"/>
public class EventLogQueryFacade: EventLogQuery {

    public string path { get; }
    public PathType pathType { get; }
    public string? query { get; }

    /// <inheritdoc cref="EventLogQuery(string, PathType)"/>
    public EventLogQueryFacade(string path, PathType pathType): base(path, pathType) {
        this.path     = path;
        this.pathType = pathType;
    }

    /// <inheritdoc cref="EventLogQuery(string, PathType, string)"/>
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

/// <inheritdoc cref="EventLogRecord"/>
public interface EventLogRecordFacade: IDisposable {

    /// <inheritdoc cref="EventLogRecord.LogName"/>
    string LogName { get; }

    /// <inheritdoc cref="EventLogRecord.Id"/>
    int Id { get; }

    /// <inheritdoc cref="EventLogRecord.RecordId"/>
    long? RecordId { get; }

    /// <inheritdoc cref="EventLogRecord.ProviderName"/>
    string ProviderName { get; }

    /// <inheritdoc cref="EventLogRecord.Properties"/>
    IList<EventPropertyFacade> Properties { get; }

    /// <inheritdoc cref="EventLogRecord.GetPropertyValues"/>
    IList<object> GetPropertyValues(EventLogPropertySelectorFacade propertySelector);

}

public class EventLogRecordFacadeImpl: EventLogRecordFacade {

    private readonly EventLogRecord record;

    public string LogName => record.LogName;
    public int Id => record.Id;
    public long? RecordId => record.RecordId;
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

/// <inheritdoc cref="EventProperty"/>
public class EventPropertyFacade {

    /// <inheritdoc cref="EventProperty.Value"/>
    public object Value { get; }

    public EventPropertyFacade(object value) {
        Value = value;
    }

    public EventPropertyFacade(EventProperty property): this(property.Value) { }

}

/// <inheritdoc cref="EventLogPropertySelector"/>
public class EventLogPropertySelectorFacade: EventLogPropertySelector {

    public IEnumerable<string> propertyQueries { get; }

    /// <inheritdoc cref="EventLogPropertySelector(IEnumerable&lt;string&gt;)"/>
    private EventLogPropertySelectorFacade(ICollection<string> propertyQueries): base(propertyQueries) {
        this.propertyQueries = propertyQueries;
    }

    /// <inheritdoc cref="EventLogPropertySelector(IEnumerable&lt;string&gt;)"/>
    public EventLogPropertySelectorFacade(IEnumerable<string> propertyQueries): this((ICollection<string>) propertyQueries) { }

}