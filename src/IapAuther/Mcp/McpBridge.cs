using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using IapAuther.Logging;
using Microsoft.Extensions.Logging;
using ModelContextProtocol;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace IapAuther.Mcp;

internal sealed class McpBridge : IAsyncDisposable
{
    private readonly ITransport _localTransport;
    private readonly IClientTransport _clientTransport;
    private readonly bool _ownsLocalTransport;
    private readonly bool _ownsClientTransport;
    private readonly TimeSpan _timeout;
    private readonly StderrLogger _logger;

    private readonly SemaphoreSlim _sessionLock = new(1, 1);
    private readonly Lock _handshakeLock = new();
    private readonly ConcurrentDictionary<WatchdogTokenSource, byte> _activeWatchdogs = new();

    private JsonRpcRequest? _cachedInitialize;
    private JsonRpcNotification? _cachedInitialized;
    private UpstreamSession? _upstreamSession;
    private int _disposed;

    public McpBridge(
        string upstream,
        HttpClient httpClient,
        HttpTransportMode transportMode = HttpTransportMode.AutoDetect,
        TimeSpan? timeout = null,
        TimeSpan? reconnectDelay = null,
        StderrLogger? logger = null,
        ITransport? localTransport = null,
        Stream? inputStream = null,
        Stream? outputStream = null,
        ILoggerFactory? sdkLoggerFactory = null)
    {
        ArgumentNullException.ThrowIfNull(upstream);
        ArgumentNullException.ThrowIfNull(httpClient);

        _timeout = timeout is { TotalMilliseconds: > 0 } t ? t : TimeSpan.FromSeconds(120);
        var effectiveReconnectDelay = reconnectDelay is { TotalMilliseconds: > 0 } rd ? rd : TimeSpan.FromSeconds(1);
        _logger = logger ?? new StderrLogger(AppLogLevel.Warn);
        var effectiveLoggerFactory = sdkLoggerFactory ?? new StderrLoggerFactory(_logger);

        if (localTransport is not null)
        {
            _localTransport = localTransport;
            _ownsLocalTransport = false;
        }
        else if (inputStream is not null && outputStream is not null)
        {
            _localTransport = new LocalStreamTransport(inputStream, outputStream, "iap-auther", effectiveLoggerFactory, leaveOpen: true);
            _ownsLocalTransport = true;
        }
        else
        {
            _localTransport = LocalStreamTransport.CreateStdio("iap-auther", effectiveLoggerFactory);
            _ownsLocalTransport = true;
        }

        _clientTransport = new HttpClientTransport(
            new HttpClientTransportOptions
            {
                Endpoint = new Uri(upstream),
                TransportMode = transportMode,
                Name = "iap-auther-upstream",
                ConnectionTimeout = _timeout,
                EnableStandaloneGetStream = true,
                OwnsSession = true,
                DefaultReconnectionInterval = effectiveReconnectDelay,
            },
            httpClient,
            effectiveLoggerFactory,
            ownsHttpClient: false);
        _ownsClientTransport = true;
    }

    public McpBridge(
        ITransport localTransport,
        IClientTransport clientTransport,
        TimeSpan? timeout = null,
        StderrLogger? logger = null,
        bool ownsLocalTransport = false,
        bool ownsClientTransport = false)
    {
        _localTransport = localTransport ?? throw new ArgumentNullException(nameof(localTransport));
        _clientTransport = clientTransport ?? throw new ArgumentNullException(nameof(clientTransport));
        _timeout = timeout is { TotalMilliseconds: > 0 } t ? t : TimeSpan.FromSeconds(120);
        _logger = logger ?? new StderrLogger(AppLogLevel.Warn);
        _ownsLocalTransport = ownsLocalTransport;
        _ownsClientTransport = ownsClientTransport;
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        var inFlight = new ConcurrentBag<Task>();

        try
        {
            await foreach (var message in _localTransport.MessageReader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
                switch (message)
                {
                    case JsonRpcRequest request when request.Method == RequestMethods.Initialize:
                        SetHandshake(ref _cachedInitialize, CloneRequest(request));
                        await ForwardWithRecoveryAsync(request, cancellationToken).ConfigureAwait(false);
                        break;

                    case JsonRpcNotification notification when notification.Method == NotificationMethods.InitializedNotification:
                        SetHandshake(ref _cachedInitialized, CloneNotification(notification));
                        await ForwardWithRecoveryAsync(notification, cancellationToken).ConfigureAwait(false);
                        break;

                    case JsonRpcRequest request when request.Method == RequestMethods.ServerDiscover:
                        await ForwardWithRecoveryAsync(request, cancellationToken).ConfigureAwait(false);
                        break;

                    default:
                        inFlight.Add(ForwardWithRecoveryAsync(message, cancellationToken));
                        break;
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }

        if (!inFlight.IsEmpty)
        {
            await Task.WhenAll(inFlight).ConfigureAwait(false);
        }
    }

    public async Task ShutdownAsync(CancellationToken cancellationToken)
    {
        UpstreamSession? session;
        await _sessionLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            session = _upstreamSession;
            _upstreamSession = null;
        }
        finally
        {
            _sessionLock.Release();
        }

        if (session is not null)
        {
            await DisposeSessionAsync(session, cancellationToken).ConfigureAwait(false);
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        using var shutdownCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try
        {
            await ShutdownAsync(shutdownCts.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.Debug("Shutdown during dispose encountered error", ("error", ex.Message));
        }

        if (_ownsClientTransport && _clientTransport is IAsyncDisposable disposableClient)
        {
            await disposableClient.DisposeAsync().ConfigureAwait(false);
        }

        if (_ownsLocalTransport)
        {
            await _localTransport.DisposeAsync().ConfigureAwait(false);
        }
    }

    private async Task ForwardWithRecoveryAsync(JsonRpcMessage message, CancellationToken outerToken)
    {
        using var watchdog = new WatchdogTokenSource(_timeout, outerToken);
        _activeWatchdogs[watchdog] = 0;

        try
        {
            UpstreamSession session;
            try
            {
                session = await GetOrCreateSessionAsync(watchdog.Token, outerToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await ReplyErrorIfRequestAsync(message, ex, watchdog, outerToken).ConfigureAwait(false);
                return;
            }

            var hadSession = !string.IsNullOrEmpty(session.Transport.SessionId);

            try
            {
                await SendWithWatchdogActivityAsync(session, message, watchdog).ConfigureAwait(false);
                return;
            }
            catch (OperationCanceledException) when (outerToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                var shouldRecover =
                    hadSession &&
                    !watchdog.IsTimedOut &&
                    GetHandshake(_cachedInitialize) is not null &&
                    await IsSessionExpiredFailureAsync(ex, session, watchdog.Token).ConfigureAwait(false);

                if (!shouldRecover)
                {
                    await ReplyErrorIfRequestAsync(message, ex, watchdog, outerToken).ConfigureAwait(false);
                    return;
                }

                UpstreamSession recoveredSession;
                try
                {
                    recoveredSession = await RecoverSessionAsync(session, outerToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (outerToken.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception recEx)
                {
                    await ReplyErrorIfRequestAsync(
                        message,
                        new InvalidOperationException($"upstream session expired and re-initialize failed: {recEx.Message}", recEx),
                        watchdog,
                        outerToken).ConfigureAwait(false);
                    return;
                }

                watchdog.Reset();
                try
                {
                    await SendWithWatchdogActivityAsync(recoveredSession, message, watchdog).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (outerToken.IsCancellationRequested)
                {
                }
                catch (Exception retryEx)
                {
                    await ReplyErrorIfRequestAsync(message, retryEx, watchdog, outerToken).ConfigureAwait(false);
                }
            }
        }
        finally
        {
            _activeWatchdogs.TryRemove(watchdog, out _);
        }
    }

    private static async Task SendWithWatchdogActivityAsync(
        UpstreamSession session,
        JsonRpcMessage message,
        WatchdogTokenSource watchdog)
    {
        using var responseWaiter = message is JsonRpcRequest request
            ? session.RegisterResponseWaiter(request.Id)
            : default;

        var previous = ActivityTrackingHandler.CurrentPostActivityCallback.Value;
        ActivityTrackingHandler.CurrentPostActivityCallback.Value = watchdog.Reset;
        try
        {
            await session.SendAsync(message, watchdog.Token).ConfigureAwait(false);
        }
        finally
        {
            ActivityTrackingHandler.CurrentPostActivityCallback.Value = previous;
        }

        if (responseWaiter.HasWaiter)
        {
            await responseWaiter.WaitAsync(watchdog.Token).ConfigureAwait(false);
        }
        else
        {
            await session.WaitForDrainAsync(watchdog.Token).ConfigureAwait(false);
        }
    }

    private async Task<UpstreamSession> GetOrCreateSessionAsync(CancellationToken connectToken, CancellationToken outerToken)
    {
        var current = Volatile.Read(ref _upstreamSession);
        if (current is not null)
        {
            return current;
        }

        await _sessionLock.WaitAsync(connectToken).ConfigureAwait(false);
        try
        {
            if (_upstreamSession is not null)
            {
                return _upstreamSession;
            }

            var transport = await _clientTransport.ConnectAsync(connectToken).ConfigureAwait(false);
            var session = new UpstreamSession(
                transport,
                msg => ForwardUpstreamMessageAsync(msg, outerToken),
                _logger);
            session.StartReading();
            Volatile.Write(ref _upstreamSession, session);
            return session;
        }
        finally
        {
            _sessionLock.Release();
        }
    }

    private async Task<UpstreamSession> RecoverSessionAsync(UpstreamSession staleSession, CancellationToken outerToken)
    {
        await _sessionLock.WaitAsync(outerToken).ConfigureAwait(false);
        try
        {
            if (!ReferenceEquals(_upstreamSession, staleSession))
            {
                return _upstreamSession
                    ?? throw new InvalidOperationException("No active upstream session available after recovery.");
            }

            var initTemplate = GetHandshake(_cachedInitialize)
                ?? throw new InvalidOperationException("no cached initialize request to replay");

            var staleSessionId = staleSession.Transport.SessionId ?? string.Empty;
            _logger.Warn("Upstream session expired; re-initializing transparently", ("stale_session", staleSessionId));

            _upstreamSession = null;
            using var staleDisposeCts = CancellationTokenSource.CreateLinkedTokenSource(outerToken);
            staleDisposeCts.CancelAfter(TimeSpan.FromSeconds(5));
            await DisposeSessionAsync(staleSession, staleDisposeCts.Token).ConfigureAwait(false);

            using var connectTimeout = new WatchdogTokenSource(_timeout, outerToken);
            var freshTransport = await _clientTransport.ConnectAsync(connectTimeout.Token).ConfigureAwait(false);
            var freshSession = new UpstreamSession(
                freshTransport,
                msg => ForwardUpstreamMessageAsync(msg, outerToken),
                _logger);

            try
            {
                var replayedInit = CloneRequest(initTemplate);
                var suppressedReply = freshSession.SuppressResponseOnce(replayedInit.Id);
                freshSession.StartReading();

                await SendPostWithActivityAsync(freshSession, replayedInit, connectTimeout).ConfigureAwait(false);
                var initResponse = await suppressedReply.WaitAsync(connectTimeout.Token).ConfigureAwait(false);
                if (initResponse is JsonRpcError initError)
                {
                    throw new InvalidOperationException(
                        $"replayed initialize returned JSON-RPC error {initError.Error.Code}: {initError.Error.Message}");
                }

                var initializedTemplate = GetHandshake(_cachedInitialized);
                if (initializedTemplate is not null)
                {
                    try
                    {
                        await SendWithWatchdogActivityAsync(freshSession, CloneNotification(initializedTemplate), connectTimeout)
                            .ConfigureAwait(false);
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        _logger.Warn("Replaying initialized notification failed", ("error", ex.Message));
                    }
                }

                Volatile.Write(ref _upstreamSession, freshSession);
                _logger.Info("Session re-established", ("session", freshTransport.SessionId ?? "(none)"));
                return freshSession;
            }
            catch
            {
                using var cleanupCts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                await DisposeSessionAsync(freshSession, cleanupCts.Token).ConfigureAwait(false);
                throw;
            }
        }
        finally
        {
            _sessionLock.Release();
        }
    }

    private async Task ForwardUpstreamMessageAsync(JsonRpcMessage message, CancellationToken outerToken)
    {
        ResetActiveWatchdogs();
        try
        {
            await _localTransport.SendMessageAsync(message, outerToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (outerToken.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            _logger.Debug("Forwarding upstream message to local transport failed", ("error", ex.Message));
        }
    }

    private void ResetActiveWatchdogs()
    {
        foreach (var kvp in _activeWatchdogs)
        {
            kvp.Key.Reset();
        }
    }

    private async Task ReplyErrorIfRequestAsync(
        JsonRpcMessage inbound,
        Exception ex,
        WatchdogTokenSource watchdog,
        CancellationToken outerToken)
    {
        if (outerToken.IsCancellationRequested)
        {
            return;
        }

        int code;
        string errorMessage;

        if (ex is McpProtocolException protocolEx)
        {
            code = (int)protocolEx.ErrorCode;
            errorMessage = protocolEx.Message;
            _logger.Error("Upstream MCP protocol error", ("code", code), ("error", errorMessage));
        }
        else if (ex is OperationCanceledException && watchdog.IsTimedOut)
        {
            code = (int)McpErrorCode.InternalError;
            errorMessage = "iap-auther: upstream request timed out";
            _logger.Error("Upstream request timed out");
        }
        else if (ex.GetType().Name == "ServerDiscoverSkippedForSseException")
        {
            code = (int)McpErrorCode.MethodNotFound;
            errorMessage = "Method 'server/discover' is not supported over legacy SSE transport.";
            _logger.Debug(errorMessage);
        }
        else
        {
            code = (int)McpErrorCode.InternalError;
            errorMessage = $"iap-auther: upstream request failed: {ex.Message}";
            _logger.Error("Upstream request failed", ("error", ex.Message));
        }

        if (inbound is not JsonRpcRequest req)
        {
            return;
        }

        var errorResponse = new JsonRpcError
        {
            Id = req.Id,
            Error = new JsonRpcErrorDetail
            {
                Code = code,
                Message = errorMessage,
            },
        };

        try
        {
            await _localTransport.SendMessageAsync(errorResponse, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception sendEx)
        {
            _logger.Debug("Writing JSON-RPC error to local transport failed", ("error", sendEx.Message));
        }
    }

    private static async Task<bool> IsSessionExpiredFailureAsync(
        Exception ex,
        UpstreamSession session,
        CancellationToken requestToken)
    {
        if (ex is HttpRequestException { StatusCode: HttpStatusCode.NotFound })
        {
            return true;
        }

        if (IsNotFoundClosureException(ex))
        {
            return true;
        }

        // If standalone GET received 404 before this request ran, SDK canceled its internal _connectionCts,
        // causing SendMessageAsync to throw OperationCanceledException even when requestToken is not canceled.
        if (ex is OperationCanceledException && !requestToken.IsCancellationRequested)
        {
            try
            {
                await Task.WhenAny(session.Transport.MessageReader.Completion, Task.Delay(50, requestToken))
                    .ConfigureAwait(false);
            }
            catch
            {
            }

            if (session.Transport.MessageReader.Completion.Exception is { } completionEx &&
                IsNotFoundClosureException(completionEx))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsNotFoundClosureException(Exception ex)
    {
        if (ex is AggregateException agg)
        {
            foreach (var inner in agg.Flatten().InnerExceptions)
            {
                if (IsNotFoundClosureException(inner))
                {
                    return true;
                }
            }
            return false;
        }

        for (Exception? cur = ex; cur is not null; cur = cur.InnerException)
        {
            if (cur is ClientTransportClosedException closed &&
                closed.Details is HttpClientCompletionDetails { HttpStatusCode: HttpStatusCode.NotFound })
            {
                return true;
            }
        }

        return false;
    }

    private static async Task DisposeSessionAsync(UpstreamSession session, CancellationToken cancellationToken)
    {
        try
        {
            var disposeTask = session.DisposeAsync().AsTask();
            if (cancellationToken.CanBeCanceled)
            {
                await disposeTask.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            else
            {
                await disposeTask.ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch
        {
        }
    }

    private void SetHandshake<T>(ref T? slot, T value) where T : class
    {
        lock (_handshakeLock)
        {
            slot = value;
        }
    }

    private T? GetHandshake<T>(T? slot) where T : class
    {
        lock (_handshakeLock)
        {
            return slot;
        }
    }

    private static JsonRpcRequest CloneRequest(JsonRpcRequest source)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(
            (JsonRpcMessage)source,
            McpJsonUtilities.ProtocolOptions.GetTypeInfo<JsonRpcMessage>());
        return (JsonRpcRequest)JsonSerializer.Deserialize(
            bytes,
            McpJsonUtilities.ProtocolOptions.GetTypeInfo<JsonRpcMessage>())!;
    }

    private static JsonRpcNotification CloneNotification(JsonRpcNotification source)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(
            (JsonRpcMessage)source,
            McpJsonUtilities.ProtocolOptions.GetTypeInfo<JsonRpcMessage>());
        return (JsonRpcNotification)JsonSerializer.Deserialize(
            bytes,
            McpJsonUtilities.ProtocolOptions.GetTypeInfo<JsonRpcMessage>())!;
    }

    private static async Task SendPostWithActivityAsync(
        UpstreamSession session,
        JsonRpcMessage message,
        WatchdogTokenSource watchdog)
    {
        var previous = ActivityTrackingHandler.CurrentPostActivityCallback.Value;
        ActivityTrackingHandler.CurrentPostActivityCallback.Value = watchdog.Reset;
        try
        {
            await session.SendAsync(message, watchdog.Token).ConfigureAwait(false);
        }
        finally
        {
            ActivityTrackingHandler.CurrentPostActivityCallback.Value = previous;
        }
    }

    private sealed class UpstreamSession : IAsyncDisposable
    {
        private readonly Func<JsonRpcMessage, Task> _onMessage;
        private readonly StderrLogger _logger;
        private readonly SemaphoreSlim _firstSendGate = new(1, 1);
        private readonly CancellationTokenSource _readerCts = new();
        private readonly Lock _suppressLock = new();
        private readonly Lock _drainLock = new();
        private readonly Lock _pendingLock = new();
        private readonly Dictionary<RequestId, TaskCompletionSource> _pendingResponses = new();

        private RequestId? _suppressedResponseId;
        private TaskCompletionSource<JsonRpcMessageWithId>? _suppressedResponseTcs;
        private TaskCompletionSource? _idleTcs;
        private bool _isProcessing;
        private bool _readerExited;
        private bool _pendingExited;
        private Exception? _readerExitException;
        private int _firstSendCompleted;
        private Task? _readerTask;
        private int _disposed;

        public UpstreamSession(
            ITransport transport,
            Func<JsonRpcMessage, Task> onMessage,
            StderrLogger logger)
        {
            Transport = transport;
            _onMessage = onMessage;
            _logger = logger;
        }

        public ITransport Transport { get; }

        public ResponseWaiterRegistration RegisterResponseWaiter(RequestId id)
        {
            var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            lock (_pendingLock)
            {
                if (_pendingExited)
                {
                    tcs.TrySetException(_readerExitException ?? new IOException("Upstream transport reader ended before receiving reply."));
                    return new ResponseWaiterRegistration(this, id, tcs, registered: false);
                }

                if (!_pendingResponses.TryAdd(id, tcs))
                {
                    return default;
                }

                return new ResponseWaiterRegistration(this, id, tcs, registered: true);
            }
        }

        private void UnregisterResponseWaiter(RequestId id, TaskCompletionSource tcs)
        {
            lock (_pendingLock)
            {
                if (_pendingResponses.TryGetValue(id, out var existing) && ReferenceEquals(existing, tcs))
                {
                    _pendingResponses.Remove(id);
                }
            }
        }

        public Task<JsonRpcMessageWithId> SuppressResponseOnce(RequestId id)
        {
            lock (_suppressLock)
            {
                _suppressedResponseId = id;
                _suppressedResponseTcs = new TaskCompletionSource<JsonRpcMessageWithId>(
                    TaskCreationOptions.RunContinuationsAsynchronously);
                return _suppressedResponseTcs.Task;
            }
        }

        public void StartReading()
        {
            _readerTask ??= Task.Run(ReadLoopAsync, CancellationToken.None);
        }

        public async Task WaitForDrainAsync(CancellationToken cancellationToken)
        {
            Task? waitTask;
            lock (_drainLock)
            {
                if (_readerTask is null || _readerExited)
                {
                    return;
                }

                if (!_isProcessing && !Transport.MessageReader.TryPeek(out _))
                {
                    return;
                }

                _idleTcs ??= new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                waitTask = _idleTcs.Task;
            }

            await waitTask.WaitAsync(cancellationToken).ConfigureAwait(false);
        }

        public async Task SendAsync(JsonRpcMessage message, CancellationToken cancellationToken)
        {
            // Serialize only the first send on a new transport so AutoDetectingClientSessionTransport
            // adopts Streamable HTTP or SSE cleanly before concurrent requests enter.
            if (Volatile.Read(ref _firstSendCompleted) == 0)
            {
                await _firstSendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
                try
                {
                    await Transport.SendMessageAsync(message, cancellationToken).ConfigureAwait(false);
                    Volatile.Write(ref _firstSendCompleted, 1);
                    return;
                }
                finally
                {
                    _firstSendGate.Release();
                }
            }

            await Transport.SendMessageAsync(message, cancellationToken).ConfigureAwait(false);
        }

        private async Task ReadLoopAsync()
        {
            Exception? loopError = null;
            try
            {
                while (await Transport.MessageReader.WaitToReadAsync(_readerCts.Token).ConfigureAwait(false))
                {
                    lock (_drainLock)
                    {
                        _isProcessing = true;
                    }

                    while (Transport.MessageReader.TryRead(out var message))
                    {
                        if (TryConsumeSuppressedResponse(message, out var tcs, out var matched))
                        {
                            tcs.TrySetResult(matched);
                            continue;
                        }

                        await _onMessage(message).ConfigureAwait(false);
                        CompleteResponseWaiter(message);
                    }

                    lock (_drainLock)
                    {
                        if (!Transport.MessageReader.TryPeek(out _))
                        {
                            _isProcessing = false;
                            _idleTcs?.TrySetResult();
                            _idleTcs = null;
                        }
                    }
                }
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                loopError = ex;
                _logger.Debug("Upstream transport reader closed", ("error", ex.Message));
            }
            finally
            {
                var completionError =
                    loopError ??
                    Transport.MessageReader.Completion.Exception?.GetBaseException() ??
                    new IOException("Upstream transport reader ended before receiving reply.");

                lock (_drainLock)
                {
                    _isProcessing = false;
                    _readerExited = true;
                    _idleTcs?.TrySetResult();
                    _idleTcs = null;
                }

                FailPendingResponses(completionError);
                FailPendingSuppression(completionError);
            }
        }

        private void CompleteResponseWaiter(JsonRpcMessage message)
        {
            if (message is not ((JsonRpcResponse or JsonRpcError) and JsonRpcMessageWithId withId))
            {
                return;
            }

            TaskCompletionSource? waiter;
            lock (_pendingLock)
            {
                _pendingResponses.Remove(withId.Id, out waiter);
            }
            waiter?.TrySetResult();
        }

        private void FailPendingResponses(Exception ex)
        {
            List<TaskCompletionSource>? pending = null;
            lock (_pendingLock)
            {
                _pendingExited = true;
                _readerExitException = ex;
                if (_pendingResponses.Count > 0)
                {
                    pending = [.. _pendingResponses.Values];
                    _pendingResponses.Clear();
                }
            }

            if (pending is not null)
            {
                foreach (var waiter in pending)
                {
                    waiter.TrySetException(ex);
                }
            }
        }

        private bool TryConsumeSuppressedResponse(
            JsonRpcMessage message,
            out TaskCompletionSource<JsonRpcMessageWithId> tcs,
            out JsonRpcMessageWithId matched)
        {
            if (message is (JsonRpcResponse or JsonRpcError) and JsonRpcMessageWithId withId)
            {
                lock (_suppressLock)
                {
                    if (_suppressedResponseId is { } targetId &&
                        withId.Id == targetId &&
                        _suppressedResponseTcs is { } pendingTcs)
                    {
                        _suppressedResponseId = null;
                        _suppressedResponseTcs = null;
                        tcs = pendingTcs;
                        matched = withId;
                        return true;
                    }
                }
            }

            tcs = null!;
            matched = null!;
            return false;
        }

        private void FailPendingSuppression(Exception ex)
        {
            TaskCompletionSource<JsonRpcMessageWithId>? pending;
            lock (_suppressLock)
            {
                pending = _suppressedResponseTcs;
                _suppressedResponseId = null;
                _suppressedResponseTcs = null;
            }
            pending?.TrySetException(ex);
        }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            try
            {
                await Transport.DisposeAsync().ConfigureAwait(false);
            }
            catch
            {
            }

            try
            {
                await _readerCts.CancelAsync().ConfigureAwait(false);
            }
            catch
            {
            }

            if (_readerTask is not null)
            {
                try
                {
                    await _readerTask.ConfigureAwait(false);
                }
                catch
                {
                }
            }

            _readerCts.Dispose();
            _firstSendGate.Dispose();
        }

        internal readonly struct ResponseWaiterRegistration : IDisposable
        {
            private readonly UpstreamSession? _session;
            private readonly RequestId _id;
            private readonly TaskCompletionSource? _tcs;
            private readonly bool _registered;

            public ResponseWaiterRegistration(
                UpstreamSession session,
                RequestId id,
                TaskCompletionSource tcs,
                bool registered)
            {
                _session = session;
                _id = id;
                _tcs = tcs;
                _registered = registered;
            }

            public bool HasWaiter => _tcs is not null;

            public Task WaitAsync(CancellationToken cancellationToken) =>
                _tcs is null ? Task.CompletedTask : _tcs.Task.WaitAsync(cancellationToken);

            public void Dispose()
            {
                if (_registered && _session is not null && _tcs is not null)
                {
                    _session.UnregisterResponseWaiter(_id, _tcs);
                }
            }
        }
    }

    private sealed class WatchdogTokenSource : IDisposable
    {
        private readonly TimeSpan _timeout;
        private readonly CancellationTokenSource _timeoutCts = new();
        private readonly CancellationTokenSource _linkedCts;
        private readonly Timer _timer;
        private int _timedOut;
        private int _disposed;

        public WatchdogTokenSource(TimeSpan timeout, CancellationToken outerToken)
        {
            _timeout = timeout;
            _linkedCts = CancellationTokenSource.CreateLinkedTokenSource(outerToken, _timeoutCts.Token);
            _timer = new Timer(_ =>
            {
                if (Volatile.Read(ref _disposed) == 0)
                {
                    Volatile.Write(ref _timedOut, 1);
                    try
                    {
                        _timeoutCts.Cancel();
                    }
                    catch (ObjectDisposedException)
                    {
                    }
                }
            }, null, timeout, Timeout.InfiniteTimeSpan);
        }

        public CancellationToken Token => _linkedCts.Token;
        public bool IsTimedOut => Volatile.Read(ref _timedOut) == 1;

        public void Reset()
        {
            if (Volatile.Read(ref _disposed) == 0)
            {
                try
                {
                    _timer.Change(_timeout, Timeout.InfiniteTimeSpan);
                }
                catch (ObjectDisposedException)
                {
                }
            }
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                _timer.Dispose();
                _linkedCts.Dispose();
                _timeoutCts.Dispose();
            }
        }
    }
}
