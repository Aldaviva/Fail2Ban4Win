#nullable enable

using NLog.Config;
using NLog.MessageTemplates;
using System.Text;

namespace Fail2Ban4Win.Logging;

/// <summary>
/// When logging strings to NLog using structured logging, don't surround them with quotation marks, because it looks stupid
/// </summary>
/// <param name="parent">Built-in <see cref="ValueFormatter"/></param>
internal sealed class UnfuckedValueFormatter(IValueFormatter parent): IValueFormatter {

    public static void register() {
        ServiceRepository services = LogManager.Configuration!.LogFactory.ServiceRepository;
        services.RegisterService(typeof(IValueFormatter), new UnfuckedValueFormatter((IValueFormatter) services.GetService(typeof(IValueFormatter))));
    }

    public bool FormatValue(object? value, string? format, CaptureType captureType, IFormatProvider? formatProvider, StringBuilder builder) {
        switch (value) {
            case string s:
                builder.Append(s);
                return true;
            case StringBuilder s:
                builder.Append(s);
                return true;
            case ReadOnlyMemory<char> s:
                builder.Append(s);
                return true;
            case char[] s:
                builder.Append(s);
                return true;
            case char s:
                builder.Append(s);
                return true;
            default:
                return parent.FormatValue(value, format, captureType, formatProvider, builder);
        }
    }

}