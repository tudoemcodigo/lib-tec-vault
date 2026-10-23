using System.Collections.Concurrent;
using System.Net;
using System.Text;
using Azure.Core;
using Azure.Core.Pipeline;
using Microsoft.Extensions.Logging;
using TEC.Vault.AzureKeyVault;
using TEC.Vault.AzureKeyVault.Internal;

namespace TEC.Vault.Tests.Fakes;

/// <summary>
/// Key Vault simulado no nível HTTP: responde ao desafio de autenticação (401 + WWW-Authenticate) como o serviço real
/// e depois devolve a resposta configurada. Permite testar o provedor inteiro, com o SDK real, sem rede.
/// </summary>
internal sealed class FakeKeyVault : HttpMessageHandler
{
    public const string VaultUri = "https://kv-teste.vault.azure.net/";
    public const string Version = "0123456789abcdef0123456789abcdef";

    private readonly Func<HttpRequestMessage, string, (HttpStatusCode Status, string Body)> _responder;

    public FakeKeyVault(Func<HttpRequestMessage, string, (HttpStatusCode Status, string Body)> responder,
        string challengeResource = "https://vault.azure.net")
    {
        _responder = responder;
        ChallengeResource = challengeResource;
    }

    public string ChallengeResource { get; }

    public ConcurrentQueue<(string Method, Uri Uri, string Body, bool Authorized)> Requests { get; } = new();

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
        bool authorized = request.Headers.Authorization is not null;
        Requests.Enqueue((request.Method.Method, request.RequestUri!, body, authorized));

        if (!authorized)
        {
            var challenge = new HttpResponseMessage(HttpStatusCode.Unauthorized) { Content = new StringContent(string.Empty) };
            challenge.Headers.TryAddWithoutValidation("WWW-Authenticate",
                $"Bearer authorization=\"https://login.microsoftonline.com/00000000-0000-0000-0000-000000000001\", resource=\"{ChallengeResource}\"");
            return challenge;
        }

        var (status, json) = _responder(request, body);
        return new HttpResponseMessage(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
    }

    /// <summary>Cria os clientes do SDK apontando para este cofre simulado.</summary>
    /// <param name="credential">Credencial falsa (para contar pedidos de token).</param>
    /// <param name="vaultUri">
    /// Host próprio do teste. O SDK guarda o desafio de autenticação em cache estático por host: testes que verificam o
    /// desafio precisam de um host que nenhum outro teste usou, senão o token já sai na primeira requisição.
    /// </param>
    /// <param name="configure">Ajustes extras nas opções (ex.: <c>MaxRetries</c>, relógio dos clientes de criptografia).</param>
    public AzureKeyVaultClients CreateClients(FakeCredential? credential = null, string vaultUri = VaultUri,
        Action<AzureKeyVaultOptions>? configure = null)
    {
        var options = new AzureKeyVaultOptions
        {
            VaultUri = new Uri(vaultUri),
            Credential = credential ?? new FakeCredential(),
            MaxRetries = 0,
            Transport = new HttpClientTransport(new HttpClient(this))
        };
        configure?.Invoke(options);
        return new AzureKeyVaultClients(options);
    }

    public static string SecretJson(string name, string value, bool enabled = true, string? contentType = "text/plain") =>
        $$$"""
        {"value":"{{{value}}}","id":"{{{VaultUri}}}secrets/{{{name}}}/{{{Version}}}","contentType":{{{(contentType is null ? "null" : $"\"{contentType}\"")}}},
         "attributes":{"enabled":{{{(enabled ? "true" : "false")}}},"created":1700000000,"updated":1700000000,"recoveryLevel":"Recoverable+Purgeable"},
         "tags":{"sistema":"teste"}}
        """;

    public static string ErrorJson(string code, string message, string? innerCode = null) =>
        innerCode is null
            ? $$$"""{"error":{"code":"{{{code}}}","message":"{{{message}}}"}}"""
            : $$$"""{"error":{"code":"{{{code}}}","message":"{{{message}}}","innererror":{"code":"{{{innerCode}}}"}""" + "}}";
}

/// <summary>Credencial falsa: conta as chamadas e registra os escopos pedidos.</summary>
internal sealed class FakeCredential : TokenCredential
{
    public int Calls;

    public ConcurrentQueue<string> Scopes { get; } = new();

    public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref Calls);
        foreach (var scope in requestContext.Scopes)
            Scopes.Enqueue(scope);
        return new AccessToken("token-falso", DateTimeOffset.UtcNow.AddHours(1));
    }

    public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
        ValueTask.FromResult(GetToken(requestContext, cancellationToken));
}

/// <summary>Logger que guarda tudo o que foi escrito (mensagem + exceção), para provar que valores sensíveis não vazam.</summary>
internal sealed class CapturingLoggerProvider : ILoggerProvider
{
    public ConcurrentQueue<(LogLevel Level, string Text)> Entries { get; } = new();

    public string AllText => string.Join('\n', Entries.Select(e => e.Text));

    public ILogger CreateLogger(string categoryName) => new CapturingLogger(this);

    public void Dispose()
    {
    }

    private sealed class CapturingLogger(CapturingLoggerProvider provider) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            provider.Entries.Enqueue((logLevel, formatter(state, exception) + (exception is null ? string.Empty : "\n" + exception)));
    }
}
