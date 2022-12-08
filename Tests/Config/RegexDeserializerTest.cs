#nullable enable

using System;
using System.ComponentModel;
using System.Text.RegularExpressions;
using Fail2Ban4Win.Config;
using Xunit;

namespace Tests.Config; 

public class RegexDeserializerTest {

    public RegexDeserializerTest() {
        RegexDeserializer.register();
    }

    [Fact]
    public void convertFromStringToRegex() {
        const string INPUT = "ab?c";

        Regex expected = new("ab?c");

        bool success = tryConvertValue(INPUT, out object? actual, out Exception? error);

        Assert.True(success);
        Assert.NotNull(actual);
        Assert.IsType<Regex>(actual);
        Assert.Equal(expected.ToString(), actual!.ToString());
        Assert.Null(error);
    }

    /// <summary>From <c>Microsoft.Extensions.Configuration.ConfigurationBinder.TryConvertValue</c></summary>
    private bool tryConvertValue(string value, out object? result, out Exception? error) {
        error  = null;
        result = null;

        TypeConverter converter = TypeDescriptor.GetConverter(typeof(Regex));
        if (converter.CanConvertFrom(typeof(string))) {
            try {
                result = converter.ConvertFromInvariantString(value);
            } catch (Exception ex) {
                error = new InvalidOperationException("failed binding", ex);
            }

            return true;
        }

        return false;
    }

}