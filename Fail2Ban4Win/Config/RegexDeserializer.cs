#nullable enable

using System.Text.RegularExpressions;

namespace Fail2Ban4Win.Config;

public sealed class RegexDeserializer: TypeConverter {

    internal static readonly TimeSpan MATCH_TIMEOUT = TimeSpan.FromSeconds(3);

    public static void register() => TypeDescriptor.AddAttributes(typeof(Regex), new TypeConverterAttribute(typeof(RegexDeserializer)));

    public override bool CanConvertFrom(ITypeDescriptorContext context, Type sourceType) => sourceType == typeof(string);

    public override object? ConvertFrom(ITypeDescriptorContext context, CultureInfo culture, object? value) =>
        value is string v ? new Regex(v, RegexOptions.None, MATCH_TIMEOUT) : null;

}