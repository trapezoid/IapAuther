using IapAuther.Cli;

namespace IapAuther.Tests;

public sealed class DurationParserTests
{
    [Theory]
    [InlineData("5m", 300_000)]
    [InlineData("120s", 120_000)]
    [InlineData("1h30m", 5_400_000)]
    [InlineData("250ms", 250)]
    [InlineData("00:05:00", 300_000)]
    public void TryParse_ValidDurations_ReturnsExpectedMilliseconds(string input, double expectedMs)
    {
        Assert.True(DurationParser.TryParse(input, out var actual));
        Assert.Equal(expectedMs, actual.TotalMilliseconds, precision: 3);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("0s")]
    [InlineData("-5m")]
    [InlineData("5")]
    [InlineData("abc")]
    public void TryParse_InvalidDurations_ReturnsFalse(string input)
    {
        Assert.False(DurationParser.TryParse(input, out _));
    }
}
