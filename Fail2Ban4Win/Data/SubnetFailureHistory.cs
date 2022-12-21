using System;

namespace Fail2Ban4Win.Data;

public interface SubnetFailureHistory {

    int banCount { get; set; }

    void clearFailures();

    void add(DateTimeOffset failureTime);

    int countFailuresSinceAndPrune(DateTimeOffset minFailureTime);

}