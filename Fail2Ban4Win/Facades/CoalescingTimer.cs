#nullable enable

using System.Threading;
using System.Threading.Tasks;

namespace Fail2Ban4Win.Facades;

public interface ICoalescingTimer: IDisposable {

    bool started { get; set; }

    void enqueue(TimeSpan delay, Action callback);

}

public sealed class CoalescingTimer: ICoalescingTimer {

    private static readonly TimeSpan MAX_DELAY;

    static CoalescingTimer() {
        try {
            // .NET ≥ 6
            MAX_DELAY = TimeSpan.FromMilliseconds(uint.MaxValue - 1);
            Task.Delay(MAX_DELAY, new CancellationToken(true)).Dispose();
        } catch (ArgumentOutOfRangeException) {
            // .NET < 6
            MAX_DELAY = TimeSpan.FromMilliseconds(int.MaxValue);
        }
    }

    private readonly LinkedList<TimerEntry> entries = new();
    private readonly Timer                  firstEntryTimer;

    private bool timerStarted;

    public CoalescingTimer(params IEnumerable<(TimeSpan delay, Action callback)> initialEntries) {
        firstEntryTimer = new Timer(onTimerElapsed, null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
        DateTimeOffset now = DateTimeOffset.Now;
        foreach ((TimeSpan delay, Action callback) in initialEntries.OrderBy(entry => entry.delay)) {
            entries.AddLast(new TimerEntry(now + delay, callback));
        }
    }

    public bool started {
        get => timerStarted;
        set {
            if (value) {
                lock (entries) {
                    if (!timerStarted && entries.First?.Value is {} firstEntry) {
                        startTimer(firstEntry);
                    }
                }
            } else {
                timerStarted = false;
                firstEntryTimer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
            }
        }
    }

    public void enqueue(TimeSpan delay, Action callback) {
        TimerEntry entry = new(DateTimeOffset.Now + delay, callback);
        lock (entries) {
            LinkedListNode<TimerEntry>? addAfterNode = entries.Last;
            while (addAfterNode is not null && entry < addAfterNode.Value) {
                addAfterNode = addAfterNode.Previous;
            }

            if (addAfterNode is not null) {
                entries.AddAfter(addAfterNode, entry);
            } else {
                entries.AddFirst(entry);
                startTimer(entry);
            }
        }
    }

    private void startTimer(TimerEntry entry) {
        timerStarted = true;
        firstEntryTimer.Change((entry.dueAt - DateTimeOffset.Now) switch {
            var tooLong when tooLong > MAX_DELAY       => MAX_DELAY,
            var negative when negative < TimeSpan.Zero => TimeSpan.Zero,
            var delay                                  => delay
        }, Timeout.InfiniteTimeSpan);
    }

    private void onTimerElapsed(object state) {
        Queue<TimerEntry> dueEntries = [];

        lock (entries) {
            for (LinkedListNode<TimerEntry>? head = entries.First; head?.Value.dueAt <= DateTimeOffset.Now; entries.RemoveFirst(), head = entries.First) {
                dueEntries.Enqueue(head.Value);
            }

            if (entries.First?.Value is {} newFirstEntry) {
                startTimer(newFirstEntry);
            } else {
                timerStarted = false;
            }
        }

        while (dueEntries.Count != 0) {
            dueEntries.Dequeue().callback();
        }
    }

    public void Dispose() {
        firstEntryTimer.Dispose();
        timerStarted = false;
        entries.Clear();
    }

    private readonly struct TimerEntry(DateTimeOffset dueAt, Action callback): IComparable<TimerEntry>, IComparable {

        public readonly DateTimeOffset dueAt    = dueAt;
        public readonly Action         callback = callback;

        public int CompareTo(TimerEntry other) => dueAt.CompareTo(other.dueAt);
        public int CompareTo(object? obj) => obj is null ? 1 : obj is TimerEntry other ? CompareTo(other) : throw new ArgumentException($"Object must be of type {nameof(TimerEntry)}");

        public static bool operator <(TimerEntry? left, TimerEntry? right) => left?.dueAt < right?.dueAt;
        public static bool operator >(TimerEntry? left, TimerEntry? right) => left?.dueAt > right?.dueAt;
        public static bool operator <=(TimerEntry? left, TimerEntry? right) => left?.dueAt <= right?.dueAt;
        public static bool operator >=(TimerEntry? left, TimerEntry? right) => left?.dueAt >= right?.dueAt;

    }

}