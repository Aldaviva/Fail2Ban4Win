#nullable enable

using System;
using System.ComponentModel;
using System.Globalization;
using System.Net;

namespace Fail2Ban4Win.Config;

public class IPNetworkDeserializer: TypeConverter {

    public static void register() {
        TypeDescriptor.AddAttributes(typeof(IPNetwork2), new TypeConverterAttribute(typeof(IPNetworkDeserializer)));
    }

    public override bool CanConvertFrom(ITypeDescriptorContext context, Type sourceType) {
        return sourceType == typeof(string);
    }

    public override object? ConvertFrom(ITypeDescriptorContext context, CultureInfo culture, object value) {
        return IPNetwork2.Parse((string) value, CidrGuess.ClassLess);
    }

}