using System;
using System.ComponentModel;
using System.Globalization;
using System.Net;

#nullable enable

namespace Fail2Ban4Win.Config {

    public class IPNetworkDeserializer: TypeConverter {

        public static void register() {
            TypeDescriptor.AddAttributes(typeof(IPNetwork), new TypeConverterAttribute(typeof(IPNetworkDeserializer)));
        }

        public override bool CanConvertFrom(ITypeDescriptorContext context, Type sourceType) {
            return sourceType == typeof(string);
        }

        public override object? ConvertFrom(ITypeDescriptorContext context, CultureInfo culture, object value) {
            return IPNetwork.Parse((string) value, CidrGuess.ClassLess);
        }

    }

}