using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace TEC.Vault.Providers;

/// <summary>
/// Trava de ambiente comum aos provedores (uso pelos provedores): recursos só de desenvolvimento (credencial de desenvolvedor,
/// provedor em memória) falham fechados fora do ambiente Development.
/// </summary>
public static class VaultEnvironment
{
    /// <summary>
    /// Ambiente de desenvolvimento? O <see cref="IHostEnvironment"/>, quando disponível, é a fonte de verdade (o ambiente pode vir
    /// de appsettings, linha de comando ou <c>WebApplicationOptions</c>, não só de variável); sem ele, <c>ASPNETCORE_ENVIRONMENT</c>
    /// e, só se ela estiver vazia, <c>DOTNET_ENVIRONMENT</c> (a mesma precedência do ASP.NET Core).
    /// </summary>
    public static bool IsDevelopment(IHostEnvironment? environment = null) =>
        IsDevelopment(environment, Environment.GetEnvironmentVariable);

    /// <summary>
    /// <see cref="IsDevelopment(IHostEnvironment?)"/> com a leitura das variáveis injetável (os testes não alteram o ambiente do
    /// processo). Uma <c>DOTNET_ENVIRONMENT=Development</c> esquecida não libera recursos de desenvolvimento quando
    /// <c>ASPNETCORE_ENVIRONMENT</c> diz outra coisa.
    /// </summary>
    internal static bool IsDevelopment(IHostEnvironment? environment, Func<string, string?> getVariable)
    {
        if (environment is not null)
            return string.Equals(environment.EnvironmentName, Environments.Development, StringComparison.OrdinalIgnoreCase);

        var name = getVariable("ASPNETCORE_ENVIRONMENT");
        if (string.IsNullOrEmpty(name))
            name = getVariable("DOTNET_ENVIRONMENT");
        return string.Equals(name, Environments.Development, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// O <see cref="IHostEnvironment"/> registrado como instância no container (o <c>WebApplicationBuilder</c>/<c>HostApplicationBuilder</c>
    /// registra antes do <c>Program.cs</c>), ou <c>null</c>.
    /// </summary>
    public static IHostEnvironment? FindHostEnvironment(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        return services.LastOrDefault(d => d.ServiceType == typeof(IHostEnvironment) && !d.IsKeyedService)?.ImplementationInstance as IHostEnvironment;
    }
}
