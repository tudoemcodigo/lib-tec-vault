using System.Net;
using System.Diagnostics.Metrics;
using System.Collections.Concurrent;
using TEC.Vault.Diagnostics;

namespace TEC.Vault.Tests.Fakes;

/// <summary>Cofre que manda os cabeçalhos (200) e para de enviar o corpo: só o tempo limite da leitura libera a chamada.</summary>
internal sealed class StallingBodyHandler : HttpMessageHandler
{
    public int Calls;

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref Calls);
        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new StallingStream()) });
    }

    private sealed class StallingStream : Stream
    {
        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position { get => 0; set => throw new NotSupportedException(); }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.Infinite, cancellationToken);
            return 0;
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}

/// <summary>Cofre que responde 200 com um corpo gigante e sem Content-Length (só o teto de leitura protege a memória).</summary>
internal sealed class GiantBodyHandler(int totalBytes) : HttpMessageHandler
{
    public int Calls;

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref Calls);
        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new RepeatingStream(totalBytes)) });
    }

    private sealed class RepeatingStream(int total) : Stream
    {
        private int _sent;

        public int Sent => _sent;

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position { get => _sent; set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var size = Math.Min(count, total - _sent);
            buffer.AsSpan(offset, size).Fill((byte)'{');
            _sent += size;
            return size;
        }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}

/// <summary>Operações registradas no histograma <c>vault.operation.duration</c> para um provedor (provedor, operação, erro).</summary>
internal sealed class OperationMetrics : IDisposable
{
    private readonly MeterListener _listener = new();

    public OperationMetrics(string provider)
    {
        _listener.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Name == VaultDiagnostics.MeterName && instrument.Name == VaultDiagnostics.OperationDurationName)
                listener.EnableMeasurementEvents(instrument);
        };
        _listener.SetMeasurementEventCallback<double>((_, _, tags, _) =>
        {
            string? tagProvider = null, operation = null, error = null;
            foreach (var tag in tags)
            {
                switch (tag.Key)
                {
                    case "vault.provider":
                        tagProvider = tag.Value as string;
                        break;
                    case "vault.operation":
                        operation = tag.Value as string;
                        break;
                    case "error.type":
                        error = tag.Value as string;
                        break;
                }
            }

            if (tagProvider == provider)
                Recorded.Enqueue((operation ?? "", error));
        });
        _listener.Start();
    }

    public ConcurrentQueue<(string Operation, string? Error)> Recorded { get; } = new();

    public void Dispose() => _listener.Dispose();
}
