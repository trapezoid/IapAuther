using Microsoft.Extensions.Logging;

namespace IapAuther.Logging;

internal sealed class StderrLoggerFactory : ILoggerFactory
{
    private readonly StderrLogger _stderrLogger;

    public StderrLoggerFactory(StderrLogger stderrLogger)
    {
        _stderrLogger = stderrLogger;
    }

    public void AddProvider(ILoggerProvider provider)
    {
        // Providers are fixed to our configured logger (stderr by default) so stdout stays clean unless explicitly requested.
    }

    public ILogger CreateLogger(string categoryName) =>
        new CategoryLogger(_stderrLogger, ShortCategory(categoryName));

    public void Dispose()
    {
    }

    private static string ShortCategory(string categoryName)
    {
        if (string.IsNullOrEmpty(categoryName))
        {
            return "mcp";
        }
        var lastDot = categoryName.LastIndexOf('.');
        return lastDot >= 0 && lastDot < categoryName.Length - 1
            ? categoryName[(lastDot + 1)..]
            : categoryName;
    }

    private sealed class CategoryLogger(StderrLogger target, string component) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) =>
            TryMapLevel(logLevel, out var appLevel) && target.IsEnabled(appLevel);

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (!TryMapLevel(logLevel, out var appLevel) || !target.IsEnabled(appLevel))
            {
                return;
            }

            var message = formatter(state, exception);
            if (string.IsNullOrEmpty(message) && exception is null)
            {
                return;
            }

            if (exception is not null)
            {
                Write(appLevel, message, ("component", component), ("error", exception.Message));
            }
            else
            {
                Write(appLevel, message, ("component", component));
            }
        }

        private void Write(AppLogLevel level, string message, params (string Key, object? Value)[] fields)
        {
            switch (level)
            {
                case AppLogLevel.Debug:
                    target.Debug(message, fields);
                    break;
                case AppLogLevel.Info:
                    target.Info(message, fields);
                    break;
                case AppLogLevel.Warn:
                    target.Warn(message, fields);
                    break;
                case AppLogLevel.Error:
                    target.Error(message, fields);
                    break;
            }
        }

        private static bool TryMapLevel(LogLevel logLevel, out AppLogLevel appLevel)
        {
            switch (logLevel)
            {
                // Intentionally skip Trace so sensitive SDK payload logs stay disabled even at --log-level debug.
                case LogLevel.Debug:
                    appLevel = AppLogLevel.Debug;
                    return true;
                case LogLevel.Information:
                    appLevel = AppLogLevel.Info;
                    return true;
                case LogLevel.Warning:
                    appLevel = AppLogLevel.Warn;
                    return true;
                case LogLevel.Error:
                case LogLevel.Critical:
                    appLevel = AppLogLevel.Error;
                    return true;
                default:
                    appLevel = AppLogLevel.Warn;
                    return false;
            }
        }
    }
}
