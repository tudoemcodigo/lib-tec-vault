using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using TEC.Vault.Abstractions;
using TEC.Vault.AzureKeyVault;
using TEC.Vault.Configuration;
using TEC.Vault.DependencyInjection;
using TEC.Vault.HashiCorpVault;
using TEC.Vault.Infisical;
using TEC.Vault.InMemory;
using TEC.Vault.Synced;

// O ambiente (DOTNET_ENVIRONMENT) escolhe o appsettings.{Ambiente}.json, e ele escolhe o cofre: nenhum if no código.
// O sample roda de qualquer pasta: appsettings e o caminho relativo "segredos-exemplo" (Staging) partem da pasta de saída
Environment.CurrentDirectory = AppContext.BaseDirectory;
var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { Args = args, ContentRootPath = AppContext.BaseDirectory });
var vault = builder.Configuration.GetSection("Vault");

// Provedores DISPONÍVEIS para a configuração escolher (compatível com Native AOT: nada é descoberto por reflexão).
// Só os pacotes referenciados aqui entram no binário.
void Providers(VaultProviderCatalog providers) => providers
    .AddInMemory()
    .AddSynced()
    .AddHashiCorpVault()
    .AddInfisical()
    .AddAzureKeyVault();

// 1º o container: a escolha do cofre é lida agora, antes de os segredos entrarem na configuração (um segredo chamado
// "MinhaApi--Vault--..." não consegue redirecionar o cofre do container)
builder.Services.AddTecVault(vault, Providers);

// Segredos com prefixo "MinhaApi--" viram configuração (ConnectionStrings:Db), lidos do cofre escolhido
builder.Configuration.AddTecVault(vault, Providers);

using var host = builder.Build();
var reader = host.Services.GetRequiredService<ISecretReader>();

Console.WriteLine($"Ambiente: {builder.Environment.EnvironmentName}");
Console.WriteLine($"Cofre de segredos: {reader.ProviderName}");
Console.WriteLine($"Chaves: {host.Services.GetService<IKeyCryptography>()?.ProviderName ?? "(nenhum provedor)"}");

var secrets = await reader.ListSecretsAsync();
if (secrets.IsFailure)
{
    Console.WriteLine($"Falha ao listar: {secrets.Error!.Code}");
    return 1;
}

foreach (var secret in secrets.Value)
    Console.WriteLine($"  segredo {secret.Name} (versão {secret.Version?[..Math.Min(8, secret.Version.Length)]})");

// O valor nunca é impresso; só a prova de que veio do cofre para o IConfiguration
Console.WriteLine($"ConnectionStrings:Db carregada do cofre: {!string.IsNullOrEmpty(builder.Configuration["ConnectionStrings:Db"])}");
return 0;
