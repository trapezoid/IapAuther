using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

namespace IapAuther.Mcp;

/// <summary>
/// SDK <see cref="TransportBase"/> implementation for stdio / stream pairs that keeps outbound writes open
/// after standard input reaches EOF so in-flight upstream responses can finish flushing to standard output.
/// </summary>
internal sealed class LocalStreamTransport : TransportBase
{
    private readonly StreamReader _inputReader;
    private readonly Stream _outputStream;
    private readonly bool _leaveOpen;
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private readonly CancellationTokenSource _shutdownCts = new();
    private readonly Task _readLoopCompleted;
    private int _disposed;

    public LocalStreamTransport(
        Stream inputStream,
        Stream outputStream,
        string serverName = "iap-auther",
        ILoggerFactory? loggerFactory = null,
        bool leaveOpen = false)
        : base($"Server (stdio) ({serverName})", loggerFactory)
    {
        ArgumentNullException.ThrowIfNull(inputStream);
        ArgumentNullException.ThrowIfNull(outputStream);

        _outputStream = outputStream;
        _leaveOpen = leaveOpen;
        _inputReader = new StreamReader(
            inputStream,
            Encoding.UTF8,
            detectEncodingFromByteOrderMarks: false,
            bufferSize: 8192,
            leaveOpen: leaveOpen);

        SetConnected();
        _readLoopCompleted = Task.Run(ReadMessagesAsync, CancellationToken.None);
    }

    public static LocalStreamTransport CreateStdio(string serverName = "iap-auther", ILoggerFactory? loggerFactory = null) =>
        new(
            new CancellableStdinStream(Console.OpenStandardInput()),
            new BufferedStream(Console.OpenStandardOutput()),
            serverName,
            loggerFactory,
            leaveOpen: false);

    public override async Task SendMessageAsync(JsonRpcMessage message, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);

        if (Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (Volatile.Read(ref _disposed) != 0)
            {
                return;
            }

            var json = JsonSerializer.SerializeToUtf8Bytes(
                message,
                McpJsonUtilities.ProtocolOptions.GetTypeInfo<JsonRpcMessage>());
            var lineBytes = new byte[json.Length + 1];
            Buffer.BlockCopy(json, 0, lineBytes, 0, json.Length);
            lineBytes[json.Length] = (byte)'\n';

            await _outputStream.WriteAsync(lineBytes, cancellationToken).ConfigureAwait(false);
            await _outputStream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _sendLock.Release();
        }
    }

    private async Task ReadMessagesAsync()
    {
        var shutdownToken = _shutdownCts.Token;
        Exception? error = null;

        try
        {
            while (!shutdownToken.IsCancellationRequested)
            {
                var line = await _inputReader.ReadLineAsync(shutdownToken).ConfigureAwait(false);
                if (line is null)
                {
                    break;
                }

                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                try
                {
                    var message = JsonSerializer.Deserialize(
                        line,
                        McpJsonUtilities.ProtocolOptions.GetTypeInfo<JsonRpcMessage>());
                    if (message is not null)
                    {
                        await WriteMessageAsync(message, shutdownToken).ConfigureAwait(false);
                    }
                }
                catch (JsonException)
                {
                    if (TryRecoverRequestId(line, out var id))
                    {
                        var parseError = new JsonRpcError
                        {
                            Id = id,
                            Error = new JsonRpcErrorDetail
                            {
                                Code = (int)McpErrorCode.ParseError,
                                Message = "Failed to parse the JSON-RPC request.",
                            },
                        };

                        try
                        {
                            await SendMessageAsync(parseError, shutdownToken).ConfigureAwait(false);
                        }
                        catch (Exception ex) when (ex is not OperationCanceledException)
                        {
                        }
                    }
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            error = ex;
        }
        finally
        {
            SetDisconnected(error);
        }
    }

    private static bool TryRecoverRequestId(string line, out RequestId id)
    {
        id = default;
        try
        {
            var utf8 = Encoding.UTF8.GetBytes(line);
            var reader = new Utf8JsonReader(utf8, new JsonReaderOptions { MaxDepth = int.MaxValue });
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                return false;
            }

            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.EndObject)
                {
                    break;
                }
                if (reader.TokenType != JsonTokenType.PropertyName)
                {
                    continue;
                }

                var isId = reader.ValueTextEquals("id"u8);
                if (!reader.Read())
                {
                    break;
                }

                if (isId)
                {
                    switch (reader.TokenType)
                    {
                        case JsonTokenType.String:
                            id = new RequestId(reader.GetString()!);
                            return true;
                        case JsonTokenType.Number when reader.TryGetInt64(out var longId):
                            id = new RequestId(longId);
                            return true;
                        default:
                            return false;
                    }
                }

                reader.Skip();
            }
        }
        catch
        {
        }

        return false;
    }

    public override async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        try
        {
            await _shutdownCts.CancelAsync().ConfigureAwait(false);

            try
            {
                await _readLoopCompleted.WaitAsync(TimeSpan.FromMilliseconds(250)).ConfigureAwait(false);
            }
            catch
            {
            }

            _inputReader.Dispose();

            try
            {
                await _readLoopCompleted.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }

            _shutdownCts.Dispose();

            await _sendLock.WaitAsync().ConfigureAwait(false);
            try
            {
                if (!_leaveOpen)
                {
                    await _outputStream.DisposeAsync().ConfigureAwait(false);
                }
            }
            finally
            {
                _sendLock.Release();
            }
        }
        finally
        {
            SetDisconnected();
        }

        GC.SuppressFinalize(this);
    }

    // Standard input streams on POSIX/Windows ignore CancellationTokens on ReadAsync;
    // wrapping with WaitAsync matches SDK StdioServerTransport cancellation behavior.
    private sealed class CancellableStdinStream(Stream stdinStream) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            stdinStream.ReadAsync(buffer, offset, count, cancellationToken).WaitAsync(cancellationToken);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var vt = stdinStream.ReadAsync(buffer, cancellationToken);
            return vt.IsCompletedSuccessfully ? vt : new(vt.AsTask().WaitAsync(cancellationToken));
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                stdinStream.Dispose();
            }
            base.Dispose(disposing);
        }

        public override void Flush() { }
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
