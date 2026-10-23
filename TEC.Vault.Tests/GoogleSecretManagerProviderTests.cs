using System.Net;
using System.Text;
using TEC.Vault.Common;
using TEC.Vault.GoogleSecretManager;

namespace TEC.Vault.Tests;

public class GoogleSecretManagerProviderTests
{
    private sealed class FakeGcpHandler : HttpMessageHandler
    {
        public HttpRequestMessage? LastRequest { get; private set; }
        public string ResponseJson { get; set; } = "{}";
        public HttpStatusCode StatusCode { get; set; } = HttpStatusCode.OK;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            var response = new HttpResponseMessage(StatusCode)
            {
                Content = new StringContent(ResponseJson, Encoding.UTF8, "application/json")
            };
            return Task.FromResult(response);
        }
    }

    [Test]
    public async Task GetSecretAsync_decodes_base64_payload_and_authorizes_with_bearer_token()
    {
        var base64Value = Convert.ToBase64String(Encoding.UTF8.GetBytes("google-secret-123"));
        var fakeHandler = new FakeGcpHandler
        {
            ResponseJson = $"{{\"name\":\"projects/my-project/secrets/db-pass/versions/1\",\"payload\":{{\"data\":\"{base64Value}\"}}}}"
        };

        var options = new GoogleSecretManagerOptions
        {
            ProjectId = "my-project",
            AccessToken = "ya29.fake-token",
            UseMetadataServer = false
        };
        options.Http.Handler = fakeHandler;

        using var store = new GoogleSecretManagerSecretStore(options);

        var result = await store.GetSecretAsync("db-pass");

        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(result.Value.Value).IsEqualTo("google-secret-123");

        var lastReq = fakeHandler.LastRequest;
        await Assert.That(lastReq).IsNotNull();
        await Assert.That(lastReq!.Headers.Authorization).IsNotNull();
        await Assert.That(lastReq.Headers.Authorization!.Scheme).IsEqualTo("Bearer");
        await Assert.That(lastReq.Headers.Authorization.Parameter).IsEqualTo("ya29.fake-token");
    }

    [Test]
    public async Task GetSecretAsync_returns_not_found_on_404()
    {
        var fakeHandler = new FakeGcpHandler
        {
            StatusCode = HttpStatusCode.NotFound,
            ResponseJson = "{\"error\":{\"code\":404,\"message\":\"Secret not found\"}}"
        };

        var options = new GoogleSecretManagerOptions
        {
            ProjectId = "my-project",
            AccessToken = "ya29.fake-token",
            UseMetadataServer = false
        };
        options.Http.Handler = fakeHandler;

        using var store = new GoogleSecretManagerSecretStore(options);

        var result = await store.GetSecretAsync("missing-secret");

        await Assert.That(result.IsFailure).IsTrue();
        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
    }
}
