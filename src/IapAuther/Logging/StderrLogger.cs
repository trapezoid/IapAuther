namespace IapAuther.Logging;

internal enum AppLogLevel
{
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3,
}

internal enum LogOutputMode
{
    Stderr = 0,
    Stdout = 1,
    Both = 2,
}

internal sealed class StderrLogger
{
    private readonly AppLogLevel _minLevel;
    private readonly LogOutputMode _outputMode;
    private readonly Lock _lock = new();
    private readonly TextWriter? _errorWriter;
    private readonly TextWriter? _outWriter;

    public StderrLogger(AppLogLevel minLevel, TextWriter? writer = null)
        : this(minLevel, LogOutputMode.Stderr, writer, null)
    {
    }

    public StderrLogger(
        AppLogLevel minLevel,
        LogOutputMode outputMode,
        TextWriter? errorWriter = null,
        TextWriter? outWriter = null)
    {
        _minLevel = minLevel;
        _outputMode = outputMode;
        _errorWriter = errorWriter;
        _outWriter = outWriter;
    }

    public LogOutputMode OutputMode => _outputMode;

    public bool IsEnabled(AppLogLevel level) => level >= _minLevel;

    public static bool TryParseLevel(string value, out AppLogLevel level)
    {
        switch (value.Trim().ToLowerInvariant())
        {
            case "debug":
                level = AppLogLevel.Debug;
                return true;
            case "info":
                level = AppLogLevel.Info;
                return true;
            case "warn":
            case "warning":
                level = AppLogLevel.Warn;
                return true;
            case "error":
                level = AppLogLevel.Error;
                return true;
            default:
                level = AppLogLevel.Warn;
                return false;
        }
    }

    public static bool TryParseOutputMode(string value, out LogOutputMode mode)
    {
        switch (value.Trim().ToLowerInvariant())
        {
            case "stderr":
                mode = LogOutputMode.Stderr;
                return true;
            case "stdout":
                mode = LogOutputMode.Stdout;
                return true;
            case "both":
                mode = LogOutputMode.Both;
                return true;
            default:
                mode = LogOutputMode.Stderr;
                return false;
        }
    }

    public void Debug(string message, params (string Key, object? Value)[] fields) =>
        Log(AppLogLevel.Debug, "DEBUG", message, fields);

    public void Info(string message, params (string Key, object? Value)[] fields) =>
        Log(AppLogLevel.Info, "INFO", message, fields);

    public void Warn(string message, params (string Key, object? Value)[] fields) =>
        Log(AppLogLevel.Warn, "WARN", message, fields);

    public void Error(string message, params (string Key, object? Value)[] fields) =>
        Log(AppLogLevel.Error, "ERROR", message, fields);

    /// <summary>
    /// Writes an unformatted diagnostic or prompt line to the configured log destination(s)
    /// regardless of the minimum structured log level.
    /// </summary>
    public void WriteLine(string line)
    {
        lock (_lock)
        {
            switch (_outputMode)
            {
                case LogOutputMode.Stderr:
                    (_errorWriter ?? Console.Error).WriteLine(line);
                    break;
                case LogOutputMode.Stdout:
                    (_outWriter ?? Console.Out).WriteLine(line);
                    break;
                case LogOutputMode.Both:
                    (_errorWriter ?? Console.Error).WriteLine(line);
                    (_outWriter ?? Console.Out).WriteLine(line);
                    break;
            }
        }
    }

    private void Log(AppLogLevel level, string tag, string message, (string Key, object? Value)[] fields)
    {
        if (level < _minLevel)
        {
            return;
        }

        var timestamp = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
        var line = fields.Length == 0
            ? $"{timestamp} level={tag} msg=\"{Escape(message)}\""
            : $"{timestamp} level={tag} msg=\"{Escape(message)}\" {FormatFields(fields)}";

        WriteLine(line);
    }

    private static string FormatFields((string Key, object? Value)[] fields)
    {
        var parts = new string[fields.Length];
        for (var i = 0; i < fields.Length; i++)
        {
            var (k, v) = fields[i];
            var str = v?.ToString() ?? "";
            parts[i] = str.Contains(' ') || str.Contains('"') || str.Length == 0
                ? $"{k}=\"{Escape(str)}\""
                : $"{k}={str}";
        }
        return string.Join(' ', parts);
    }

    private static string Escape(string value) =>
        value.Replace("\\", "\\\\", StringComparison.Ordinal)
             .Replace("\"", "\\\"", StringComparison.Ordinal)
             .Replace("\r", "\\r", StringComparison.Ordinal)
             .Replace("\n", "\\n", StringComparison.Ordinal);
}
