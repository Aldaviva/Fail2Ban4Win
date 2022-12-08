#nullable enable

using System;
using System.ComponentModel;
using System.Globalization;
using System.Text.RegularExpressions;

namespace Fail2Ban4Win.Config; 

public class RegexDeserializer: TypeConverter {

    public static void register() {
        TypeDescriptor.AddAttributes(typeof(Regex), new TypeConverterAttribute(typeof(RegexDeserializer)));
    }

    public override bool CanConvertFrom(ITypeDescriptorContext context, Type sourceType) {
        return sourceType == typeof(string);
    }

    public override object ConvertFrom(ITypeDescriptorContext context, CultureInfo culture, object value) {
        return new Regex((string) value);
    }

}