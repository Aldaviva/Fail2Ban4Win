using System;
using System.Collections.Generic;

namespace Fail2Ban4Win.Data; 

public class ArrayListSubnetFailureHistory: SubnetFailureHistory {

    private readonly List<DateTimeOffset> failureTimes;

    public ArrayListSubnetFailureHistory(int maxFailuresAllowed) {
        failureTimes = new List<DateTimeOffset>(maxFailuresAllowed + 1);
    }

    public int banCount { get; set; }

    public void clear() {
        failureTimes.Clear();
    }

    public void add(DateTimeOffset failureTime) {
        failureTimes.Add(failureTime);
    }

    public int countFailuresSinceAndPrune(DateTimeOffset minFailureTime) {
        failureTimes.RemoveAll(offset => offset < minFailureTime);
        return failureTimes.Count;
    }

}