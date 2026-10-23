using Microsoft.Extensions.Hosting;
using TEC.Vault.DependencyInjection;

namespace TEC.Vault.InMemory;

/// <summary>Configuração do provedor em memória (somente desenvolvimento local e testes automatizados).</summary>
public sealed class InMemoryVaultOptions
{
    /// <summary>
    /// Permite usar o provedor fora do ambiente Development. Padrão: <c>false</c> (falha fechada: um servidor nunca passa a
    /// guardar segredos em memória por engano de configuração). Use <c>true</c> em testes automatizados, cujo processo
    /// normalmente não tem ambiente definido.
    /// </summary>
    public bool AllowOutsideDevelopment { get; set; }

    /// <summary>
    /// Ambiente da aplicação, usado na trava de Development. <c>null</c> (padrão): <c>UseInMemory</c> usa o
    /// <see cref="IHostEnvironment"/> registrado no container e, sem ele, as variáveis <c>ASPNETCORE_ENVIRONMENT</c>/<c>DOTNET_ENVIRONMENT</c>.
    /// </summary>
    public IHostEnvironment? HostEnvironment { get; set; }

    /// <summary>Relógio (datas de criação, validade, exclusão). Padrão: <see cref="System.TimeProvider.System"/>.</summary>
    public TimeProvider? TimeProvider { get; set; }

    /// <summary>
    /// Máximo de backups guardados por store (cada backup é uma cópia completa das versões, inclusive chaves privadas). Ao passar
    /// do limite, o backup mais antigo é descartado (os bytes das chaves privadas dele são zerados) e o identificador dele deixa
    /// de ser aceito na restauração. Padrão: 100.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">Valor menor que 1.</exception>
    public int MaxBackups
    {
        get;
        set => field = value >= 1 ? value : throw new ArgumentOutOfRangeException(nameof(MaxBackups), "Informe ao menos 1 backup.");
    } = 100;

    /// <summary>Stores registrados por <c>UseInMemory</c>. Padrão: <see cref="VaultStores.All"/>.</summary>
    public VaultStores Stores { get; set; } = VaultStores.All;

    /// <summary>
    /// Segredos iniciais (nome → valor), gravados na criação do store de segredos. Útil para subir a aplicação localmente
    /// sem cofre real. Não coloque segredos reais aqui: use valores de desenvolvimento.
    /// </summary>
    public IDictionary<string, string> InitialSecrets { get; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
}
