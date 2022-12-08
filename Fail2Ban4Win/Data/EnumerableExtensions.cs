#nullable enable

using System.Collections.Generic;
using System.Linq;

// ReSharper disable InconsistentNaming - library functions that are supposed to look like Linq methods, which user UpperCase naming.

namespace Fail2Ban4Win.Data; 

public static class EnumerableExtensions {

    /// <summary>Remove null values.</summary>
    /// <returns>Input enumerable with null values removed.</returns>
    public static IEnumerable<T> Compact<T>(this IEnumerable<T?> source) where T: class {
        return source.Where(item => item is not null)!;
    }

}