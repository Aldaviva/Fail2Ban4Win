using System;
using System.ComponentModel;
using System.Globalization;
using System.Text.RegularExpressions;

#nullable enable

namespace Fail2Ban4Win.Config {

    public class RegexConverter: TypeConverter {

        public static void register() {
            TypeDescriptor.AddAttributes(typeof(Regex), new TypeConverterAttribute(typeof(RegexConverter)));
        }

        public override bool CanConvertFrom(ITypeDescriptorContext context, Type sourceType) {
            return sourceType == typeof(string) || sourceType == typeof(Regex) || base.CanConvertFrom(context, sourceType);
        }

        public override bool CanConvertTo(ITypeDescriptorContext context, Type destinationType) {
            return destinationType == typeof(string) || destinationType == typeof(Regex) || base.CanConvertTo(context, destinationType);
        }

        public override object? ConvertFrom(ITypeDescriptorContext context, CultureInfo culture, object value) {
            return value switch {
                Regex              => value,
                string valueString => new Regex(valueString),
                _                  => base.ConvertFrom(context, culture, value)
            };
        }

        public override object? ConvertTo(ITypeDescriptorContext context, CultureInfo culture, object value, Type destinationType) {
            if (value is Regex regex) {
                if (destinationType == typeof(Regex)) {
                    return regex;
                } else if (destinationType == typeof(string)) {
                    return regex.ToString();
                }
            }

            return base.ConvertTo(context, culture, value, destinationType);
        }

    }

}