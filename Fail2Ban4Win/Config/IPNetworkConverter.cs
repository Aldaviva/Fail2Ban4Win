using System;
using System.ComponentModel;
using System.Globalization;
using System.Net;

#nullable enable

namespace Fail2Ban4Win.Config {

    public class IPNetworkConverter: TypeConverter {

        public static void register() {
            TypeDescriptor.AddAttributes(typeof(IPNetwork), new TypeConverterAttribute(typeof(IPNetworkConverter)));
        }

        public override bool CanConvertFrom(ITypeDescriptorContext context, Type sourceType) {
            return sourceType == typeof(string) || sourceType == typeof(IPNetwork) || base.CanConvertFrom(context, sourceType);
        }

        public override bool CanConvertTo(ITypeDescriptorContext context, Type destinationType) {
            return destinationType == typeof(string) || destinationType == typeof(IPNetwork) || base.CanConvertTo(context, destinationType);
        }

        public override object? ConvertFrom(ITypeDescriptorContext context, CultureInfo culture, object value) {
            return value switch {
                IPNetwork          => value,
                string valueString => IPNetwork.Parse(valueString, CidrGuess.ClassLess),
                _                  => base.ConvertFrom(context, culture, value)
            };
        }

        public override object? ConvertTo(ITypeDescriptorContext context, CultureInfo culture, object value, Type destinationType) {
            if (value is IPNetwork ipNetwork) {
                if (destinationType == typeof(IPNetwork)) {
                    return ipNetwork;
                } else if (destinationType == typeof(string)) {
                    return ipNetwork.ToString();
                }
            }

            return base.ConvertTo(context, culture, value, destinationType);
        }

    }

}