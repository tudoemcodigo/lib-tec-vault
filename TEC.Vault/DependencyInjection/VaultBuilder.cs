using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.DependencyInjection;
using TEC.Vault.Abstractions;
using TEC.Vault.Caching;

namespace TEC.Vault.DependencyInjection;

/// <summary>Configuração do <c>AddTecVault</c>: escolha do provedor e opções gerais.</summary>
/// <remarks>
/// Um cofre por aplicação: cada família (segredos, chaves, certificados) aceita um único provedor. A classe informada é
/// registrada como singleton e <b>cada interface que ela implementa</b> (leitura, gestão, criptografia, lixeira, backup)
/// aponta para a mesma instância. Uma classe que implementa mais de uma família também é uma única instância.
/// <para>Os <c>Use*Store</c> lançam <see cref="InvalidOperationException"/> quando o registro seria ignorado em silêncio: a classe
/// do provedor já registrada no container antes do <c>AddTecVault</c>, ou a mesma classe informada de novo com outra fábrica
/// (ou com e sem fábrica). Repetir a mesma classe sem fábrica, ou com a mesma fábrica, é aceito.</para>
/// </remarks>
public sealed class VaultBuilder
{
    internal VaultBuilder(IServiceCollection services) => Services = services;

    /// <summary>Container, para os provedores registrarem as suas dependências.</summary>
    public IServiceCollection Services { get; }

    /// <summary>Implementação escolhida para uma família e como obtê-la do container.</summary>
    internal sealed record Registration(Type ImplementationType, Func<IServiceProvider, object> Resolve);

    internal Registration? Secrets { get; private set; }

    internal Registration? Keys { get; private set; }

    internal Registration? Certificates { get; private set; }

    internal TimeSpan? SecretCacheDuration { get; private set; }

    /// <summary>
    /// Define o provedor de segredos (uso pelos provedores). Registra <typeparamref name="T"/> como singleton e, conforme o que ele
    /// implementa, <see cref="ISecretReader"/>, <see cref="ISecretStore"/>, <see cref="ISecretRecycleBin"/> e <see cref="ISecretBackup"/>.
    /// </summary>
    public VaultBuilder UseSecretStore<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] T>()
        where T : class, ISecretReader
    {
        Secrets = Set(Secrets, typeof(T), "segredos");
        return AddType<T>();
    }

    /// <summary>Como <see cref="UseSecretStore{T}()"/>, criando a instância com <paramref name="factory"/> (ex.: construtor interno).</summary>
    /// <remarks><typeparamref name="T"/> deve ser a classe concreta: as interfaces registradas são as que ela implementa.</remarks>
    /// <exception cref="InvalidOperationException">
    /// <typeparamref name="T"/> já registrado no container, ou já configurado com outra fábrica (a nova seria ignorada).
    /// </exception>
    public VaultBuilder UseSecretStore<T>(Func<IServiceProvider, T> factory) where T : class, ISecretReader
    {
        ArgumentNullException.ThrowIfNull(factory);
        Secrets = Set(Secrets, typeof(T), "segredos");
        return AddFactory(factory);
    }

    /// <summary>
    /// Define o provedor de chaves (uso pelos provedores). <typeparamref name="T"/> precisa implementar <see cref="IKeyReader"/>
    /// e/ou <see cref="IKeyCryptography"/>; são registradas também <see cref="IKeyStore"/>, <see cref="IKeyRecycleBin"/> e
    /// <see cref="IKeyBackup"/>, se implementadas.
    /// </summary>
    /// <exception cref="ArgumentException"><typeparamref name="T"/> não implementa nenhuma interface de chaves.</exception>
    public VaultBuilder UseKeyStore<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] T>() where T : class
    {
        Keys = Set(Keys, EnsureKeyProvider(typeof(T)), "chaves");
        return AddType<T>();
    }

    /// <summary>Como <see cref="UseKeyStore{T}()"/>, criando a instância com <paramref name="factory"/>.</summary>
    public VaultBuilder UseKeyStore<T>(Func<IServiceProvider, T> factory) where T : class
    {
        ArgumentNullException.ThrowIfNull(factory);
        Keys = Set(Keys, EnsureKeyProvider(typeof(T)), "chaves");
        return AddFactory(factory);
    }

    /// <summary>
    /// Define o provedor de certificados (uso pelos provedores). Registra <see cref="ICertificateReader"/> e, se implementadas,
    /// <see cref="ICertificateStore"/>, <see cref="ICertificateRecycleBin"/> e <see cref="ICertificateBackup"/>.
    /// </summary>
    public VaultBuilder UseCertificateStore<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] T>()
        where T : class, ICertificateReader
    {
        Certificates = Set(Certificates, typeof(T), "certificados");
        return AddType<T>();
    }

    /// <summary>Como <see cref="UseCertificateStore{T}()"/>, criando a instância com <paramref name="factory"/>.</summary>
    public VaultBuilder UseCertificateStore<T>(Func<IServiceProvider, T> factory) where T : class, ICertificateReader
    {
        ArgumentNullException.ThrowIfNull(factory);
        Certificates = Set(Certificates, typeof(T), "certificados");
        return AddFactory(factory);
    }

    /// <summary>
    /// Ativa o cache em memória das leituras de segredos (desligado por padrão). Reduz latência e o risco de throttling do cofre,
    /// ao custo de manter valores em memória e de ver rotações feitas por outras instâncias só após <paramref name="duration"/>.
    /// </summary>
    /// <remarks>
    /// <para><b>Escritas devem passar pelas interfaces</b> (<see cref="ISecretStore"/>, <see cref="ISecretRecycleBin"/>,
    /// <see cref="ISecretBackup"/>): com o cache ativo elas são decorators que limpam o cache após cada escrita. A classe
    /// concreta do provedor (ex.: <c>AzureKeyVaultSecretStore</c>) continua registrada no container (contrato do
    /// <c>UseSecretStore</c>) e grava direto no cofre, <b>sem</b> limpar o cache: quem a injeta para escrever deixa as leituras
    /// com o valor antigo até <paramref name="duration"/>. Injete a classe concreta só para leitura sem cache.</para>
    /// </remarks>
    /// <param name="duration">Duração (maior que zero, máximo 1 hora). Recomendado: até 5 minutos.</param>
    public VaultBuilder EnableSecretCache(TimeSpan duration)
    {
        CachingSecretReader.ValidateDuration(duration);
        SecretCacheDuration = duration;
        return this;
    }

    /// <summary>
    /// Registra, de uma vez, os stores escolhidos em <paramref name="stores"/> (uso pelos provedores que oferecem as três
    /// famílias e uma opção <c>Stores</c>): cada fábrica só é registrada se a família estiver selecionada.
    /// </summary>
    /// <param name="stores">Stores selecionados (ao menos um; veja <see cref="EnsureValidStores"/>).</param>
    /// <param name="secrets">Fábrica do store de segredos.</param>
    /// <param name="keys">Fábrica do store de chaves.</param>
    /// <param name="certificates">Fábrica do store de certificados.</param>
    /// <exception cref="InvalidOperationException"><paramref name="stores"/> vazio ou com valor desconhecido.</exception>
    public VaultBuilder UseStores<TSecrets, TKeys, TCertificates>(VaultStores stores, Func<IServiceProvider, TSecrets> secrets,
        Func<IServiceProvider, TKeys> keys, Func<IServiceProvider, TCertificates> certificates)
        where TSecrets : class, ISecretReader
        where TKeys : class
        where TCertificates : class, ICertificateReader
    {
        ArgumentNullException.ThrowIfNull(secrets);
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentNullException.ThrowIfNull(certificates);
        EnsureValidStores(stores, nameof(stores));

        if (stores.HasFlag(VaultStores.Secrets))
            UseSecretStore(secrets);
        if (stores.HasFlag(VaultStores.Keys))
            UseKeyStore(keys);
        if (stores.HasFlag(VaultStores.Certificates))
            UseCertificateStore(certificates);

        return this;
    }

    /// <summary>Confere a opção <c>Stores</c> de um provedor: ao menos um store e nenhum valor desconhecido.</summary>
    /// <param name="stores">Valor da opção.</param>
    /// <param name="optionName">Nome da opção para a mensagem (ex.: "AzureKeyVaultOptions.Stores").</param>
    /// <exception cref="InvalidOperationException">Opção inválida.</exception>
    public static void EnsureValidStores(VaultStores stores, string optionName)
    {
        if (stores == VaultStores.None || (stores & ~VaultStores.All) != 0)
            throw new InvalidOperationException($"{optionName} deve conter ao menos um store válido.");
    }

    // Classes de provedor registradas por este builder → fábrica usada (null = ativação pelo container). Uma classe pode atender
    // mais de uma família, mas sempre com o mesmo registro: uma segunda fábrica seria descartada em silêncio pelo container
    private readonly Dictionary<Type, Delegate?> _registered = [];

    private VaultBuilder AddType<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] T>() where T : class
    {
        if (Track(typeof(T), factory: null))
            Services.AddSingleton<T>();
        return this;
    }

    private VaultBuilder AddFactory<T>(Func<IServiceProvider, T> factory) where T : class
    {
        if (Track(typeof(T), factory))
            Services.AddSingleton(factory);
        return this;
    }

    /// <summary>
    /// Confere se <paramref name="type"/> pode ser registrado e se ainda precisa ser. <c>false</c> = já registrado por este builder
    /// com o mesmo registro (classe que atende mais de uma família ou chamada repetida sem fábrica).
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// A classe já estava no container antes do <c>AddTecVault</c>, ou foi informada de novo com outra fábrica (ou com e sem fábrica).
    /// </exception>
    private bool Track(Type type, Delegate? factory)
    {
        if (_registered.TryGetValue(type, out var previous))
        {
            if ((previous is null && factory is null) || (previous is not null && previous.Equals(factory)))
                return false;

            throw new InvalidOperationException(
                $"{type.Name} já foi configurado como provedor do cofre com outra forma de criação (fábrica diferente, ou com e sem fábrica). " +
                "A segunda seria ignorada pelo container: use uma única fábrica (ou nenhuma) para a mesma classe.");
        }

        if (Services.Any(d => d.ServiceType == type))
        {
            throw new InvalidOperationException(
                $"{type.Name} já está registrado no container. O AddTecVault registra a classe do provedor; remova o registro anterior " +
                "ou informe a criação pela fábrica do Use*Store (o registro existente faria a configuração do cofre ser ignorada).");
        }

        _registered[type] = factory;
        return true;
    }

    private static Type EnsureKeyProvider(Type type) =>
        typeof(IKeyReader).IsAssignableFrom(type) || typeof(IKeyCryptography).IsAssignableFrom(type)
            ? type
            : throw new ArgumentException($"{type.Name} não implementa IKeyReader nem IKeyCryptography.", "T");

    private static Registration Set(Registration? current, Type type, string family)
    {
        if (current is not null && current.ImplementationType != type)
        {
            throw new InvalidOperationException(
                $"Já existe um provedor configurado para {family} ({current.ImplementationType.Name}). Configure apenas um provedor (um cofre por aplicação).");
        }

        return new Registration(type, sp => sp.GetRequiredService(type));
    }
}
