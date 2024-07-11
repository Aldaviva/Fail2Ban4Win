#nullable enable

using Fail2Ban4Win.Config;
using System;
using System.ComponentModel;
using System.Net;
using Xunit;

namespace Tests.Config;

public class IPNetworkDeserializerTest {

    public IPNetworkDeserializerTest() {
        IPNetworkDeserializer.register();
    }

    [Fact]
    public void convertFromStringWithCidrToIPNetwork() {
        const string INPUT = "127.0.0.1/8";

        IPNetwork2 expected = IPNetwork2.Parse("127.0.0.1", 8);

        bool success = tryConvertValue(INPUT, out object? actual, out Exception? error);

        Assert.True(success);
        Assert.NotNull(actual);
        Assert.IsType<IPNetwork2>(actual);
        Assert.Equal(expected, actual);
        Assert.Null(error);
    }

    [Fact]
    public void convertFromStringWithoutCidrToIPNetwork() {
        const string INPUT = "67.210.32.33";

        IPNetwork2 expected = IPNetwork2.Parse("67.210.32.33", 32);

        bool success = tryConvertValue(INPUT, out object? actual, out Exception? _);

        Assert.True(success);
        Assert.Equal(expected, actual);
    }

    /// <summary>From <c>Microsoft.Extensions.Configuration.ConfigurationBinder.TryConvertValue</c></summary>
    private bool tryConvertValue(string value, out object? result, out Exception? error) {
        error  = null;
        result = null;

        TypeConverter converter = TypeDescriptor.GetConverter(typeof(IPNetwork2));
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