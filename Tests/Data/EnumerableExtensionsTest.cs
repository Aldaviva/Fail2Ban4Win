using System.Collections.Generic;
using Fail2Ban4Win.Data;
using Xunit;

#nullable enable

namespace Tests.Data {

    public class EnumerableExtensionsTest {

        [Fact]
        public void classes() {
            IEnumerable<string?> input    = new[] { "hello", null, "world" };
            IEnumerable<string>  actual   = input.Compact();
            IEnumerable<string>  expected = new[] { "hello", "world" };

            Assert.Equal(expected, actual);
        }

    }

}