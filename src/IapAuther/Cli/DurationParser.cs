using System.Globalization;
using System.Text.RegularExpressions;

namespace IapAuther.Cli;

internal static partial class DurationParser
{
    public static bool TryParse(string? input, out TimeSpan result)
    {
        result = default;
        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        var trimmed = input.Trim();
        if (TimeSpan.TryParse(trimmed, CultureInfo.InvariantCulture, out var parsed) &&
            !trimmed.All(char.IsDigit))
        {
            result = parsed;
            return result > TimeSpan.Zero;
        }

        // Go-style compound durations such as "5m", "120s", "1h30m", "250ms".
        var matches = TokenRegex().Matches(trimmed);
        if (matches.Count == 0)
        {
            return false;
        }

        var consumed = 0;
        var total = TimeSpan.Zero;
        foreach (Match m in matches)
        {
            if (m.Index != consumed)
            {
                return false;
            }
            consumed += m.Length;

            if (!double.TryParse(m.Groups[1].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out var num))
            {
                return false;
            }

            total += m.Groups[2].Value switch
            {
                "ns" => TimeSpan.FromTicks((long)(num / 100.0)),
                "us" or "µs" => TimeSpan.FromMicroseconds(num),
                "ms" => TimeSpan.FromMilliseconds(num),
                "s" => TimeSpan.FromSeconds(num),
                "m" => TimeSpan.FromMinutes(num),
                "h" => TimeSpan.FromHours(num),
                _ => TimeSpan.Zero,
            };
        }

        if (consumed != trimmed.Length || total <= TimeSpan.Zero)
        {
            return false;
        }

        result = total;
        return true;
    }

    [GeneratedRegex(@"(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)", RegexOptions.CultureInvariant)]
    private static partial Regex TokenRegex();
}
