using System;
using Microsoft.UI;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Media;

namespace AdblockApp.Converters;

public class StringFormatConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        if (parameter is string format)
        {
            return string.Format(format, value);
        }
        return value?.ToString() ?? "";
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language)
    {
        throw new NotImplementedException();
    }
}

public class ActionColorConverter : IValueConverter
{
    private static readonly SolidColorBrush BlockedBrush = new(Windows.UI.Color.FromArgb(255, 239, 83, 80)); // Red
    private static readonly SolidColorBrush AllowedBrush = new(Windows.UI.Color.FromArgb(255, 102, 187, 106)); // Green
    private static readonly SolidColorBrush DroppedBrush = new(Windows.UI.Color.FromArgb(255, 255, 167, 38)); // Orange

    public object Convert(object value, Type targetType, object parameter, string language)
    {
        string action = value?.ToString()?.ToUpperInvariant() ?? "";
        return action switch
        {
            "BLOCKED" => BlockedBrush,
            "DROPPED" => DroppedBrush,
            _ => AllowedBrush
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language)
    {
        throw new NotImplementedException();
    }
}
