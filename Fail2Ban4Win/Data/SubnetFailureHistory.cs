using System;

namespace Fail2Ban4Win.Data; 

public interface SubnetFailureHistory {

    int banCount { get; set; }

    void clear();

    void add(DateTimeOffset failureTime);

    int countFailuresSinceAndPrune(DateTimeOffset minFailureTime);

}