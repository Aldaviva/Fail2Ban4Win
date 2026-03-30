#nullable enable

namespace Fail2Ban4Win.Config;

public sealed class IPNetworkDeserializer: TypeConverter {

    public static void register() => TypeDescriptor.AddAttributes(typeof(IPNetwork2), new TypeConverterAttribute(typeof(IPNetworkDeserializer)));

    public override bool CanConvertFrom(ITypeDescriptorContext context, Type sourceType) => sourceType == typeof(string);

    public override object? ConvertFrom(ITypeDescriptorContext context, CultureInfo culture, object? value) =>
        value is string v ? IPNetwork2.Parse(v, CidrGuess.ClassLess) : null;

}