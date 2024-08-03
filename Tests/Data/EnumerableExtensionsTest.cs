#nullable enable

using Fail2Ban4Win.Data;
using System.Collections.Generic;
using Xunit;

namespace Tests.Data;

public class EnumerableExtensionsTest {

    [Fact]
    public void classes() {
        IEnumerable<string?> input    = ["hello", null, "world"];
        IEnumerable<string>  actual   = input.Compact();
        IEnumerable<string>  expected = ["hello", "world"];

        Assert.Equal(expected, actual);
    }

}