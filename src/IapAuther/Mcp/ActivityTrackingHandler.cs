using System.Net;

namespace IapAuther.Mcp;

/// <summary>
/// Tracks byte-level read activity on POST HTTP response streams (including SSE comments/keepalives)
/// so the idle timeout watchdog resets even before a full JSON-RPC event arrives.
/// </summary>
internal sealed class ActivityTrackingHandler : DelegatingHandler
{
    internal static readonly AsyncLocal<Action?> CurrentPostActivityCallback = new();

    public ActivityTrackingHandler(HttpMessageHandler innerHandler)
        : base(innerHandler)
    {
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var callback = request.Method == HttpMethod.Post ? CurrentPostActivityCallback.Value : null;
        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

        if (callback is not null && response.Content is { } originalContent)
        {
            response.Content = new ActivityHttpContent(originalContent, callback);
        }

        return response;
    }

    private sealed class ActivityHttpContent : HttpContent
    {
        private readonly HttpContent _inner;
        private readonly Action _onActivity;

        public ActivityHttpContent(HttpContent inner, Action onActivity)
        {
            _inner = inner;
            _onActivity = onActivity;
            foreach (var header in inner.Headers)
            {
                Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
        }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
            _inner.CopyToAsync(stream, context);

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context, CancellationToken cancellationToken) =>
            _inner.CopyToAsync(stream, context, cancellationToken);

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }

        protected override async Task<Stream> CreateContentReadStreamAsync(CancellationToken cancellationToken)
        {
            var innerStream = await _inner.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            return new ActivityStream(innerStream, _onActivity);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _inner.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    private sealed class ActivityStream(Stream inner, Action onActivity) : Stream
    {
        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var n = inner.Read(buffer, offset, count);
            if (n > 0)
            {
                onActivity();
            }
            return n;
        }

        public override int Read(Span<byte> buffer)
        {
            var n = inner.Read(buffer);
            if (n > 0)
            {
                onActivity();
            }
            return n;
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var n = await inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (n > 0)
            {
                onActivity();
            }
            return n;
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            var n = await inner.ReadAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
            if (n > 0)
            {
                onActivity();
            }
            return n;
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                inner.Dispose();
            }
            base.Dispose(disposing);
        }

        public override ValueTask DisposeAsync() => inner.DisposeAsync();
    }
}
