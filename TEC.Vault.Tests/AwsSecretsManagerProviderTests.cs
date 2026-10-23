using System.Net;
using System.Text;
using TEC.Vault.AwsSecretsManager;
using TEC.Vault.Common;

namespace TEC.Vault.Tests;

public class AwsSecretsManagerProviderTests
{
    private sealed class FakeAwsHandler : HttpMessageHandler
    {
        public HttpRequestMessage? LastRequest { get; private set; }
        public string ResponseJson { get; set; } = "{}";
        public HttpStatusCode StatusCode { get; set; } = HttpStatusCode.OK;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            var response = new HttpResponseMessage(StatusCode)
            {
                Content = new StringContent(ResponseJson, Encoding.UTF8, "application/x-amz-json-1.1")
            };
            return Task.FromResult(response);
        }
    }

    [Test]
    public async Task GetSecretAsync_signs_request_and_parses_aws_response()
    {
        var fakeHandler = new FakeAwsHandler
        {
            ResponseJson = "{\"ARN\":\"arn:aws:secretsmanager:sa-east-1:12345:secret:app-key\",\"Name\":\"app-key\",\"VersionId\":\"v1\",\"SecretString\":\"super-secret-value\"}"
        };

        var options = new AwsSecretsManagerOptions
        {
            Region = "sa-east-1",
            AccessKeyId = "AKIAIOSFODNN7EXAMPLE",
            SecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        };
        options.Http.Handler = fakeHandler;

        using var store = new AwsSecretsManagerSecretStore(options);

        var result = await store.GetSecretAsync("app-key");

        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(result.Value.Value).IsEqualTo("super-secret-value");

        // Valida que o cabeçalho Authorization foi adicionado com SigV4
        var lastReq = fakeHandler.LastRequest;
        await Assert.That(lastReq).IsNotNull();
        await Assert.That(lastReq!.Headers.Contains("x-amz-target")).IsTrue();
        await Assert.That(lastReq.Headers.Contains("x-amz-date")).IsTrue();
        await Assert.That(lastReq.Headers.TryGetValues("Authorization", out var authValues)).IsTrue();
        await Assert.That(authValues!.First()).StartsWith("AWS4-HMAC-SHA256");
    }

    [Test]
    public async Task GetSecretAsync_returns_not_found_on_ResourceNotFoundException()
    {
        var fakeHandler = new FakeAwsHandler
        {
            StatusCode = HttpStatusCode.BadRequest,
            ResponseJson = "{\"__type\":\"ResourceNotFoundException\",\"Message\":\"Secrets Manager can't find the specified secret.\"}"
        };

        var options = new AwsSecretsManagerOptions
        {
            Region = "sa-east-1",
            AccessKeyId = "AKIAIOSFODNN7EXAMPLE",
            SecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        };
        options.Http.Handler = fakeHandler;

        using var store = new AwsSecretsManagerSecretStore(options);

        var result = await store.GetSecretAsync("missing-secret");

        await Assert.That(result.IsFailure).IsTrue();
        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
    }

    [Test]
    public async Task SetSecretAsync_creates_secret_successfully()
    {
        var fakeHandler = new FakeAwsHandler
        {
            ResponseJson = "{\"ARN\":\"arn:aws:secretsmanager:sa-east-1:12345:secret:new-secret\",\"Name\":\"new-secret\",\"VersionId\":\"v1\"}"
        };

        var options = new AwsSecretsManagerOptions
        {
            Region = "sa-east-1",
            AccessKeyId = "AKIAIOSFODNN7EXAMPLE",
            SecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        };
        options.Http.Handler = fakeHandler;

        using var store = new AwsSecretsManagerSecretStore(options);

        var result = await store.SetSecretAsync("new-secret", "some-value");

        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(result.Value.Version).IsEqualTo("v1");
    }
}
