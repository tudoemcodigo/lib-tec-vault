using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using TEC.Vault.Abstractions;
using TEC.Vault.Certificates;
using TEC.Vault.Common;
using TEC.Vault.HashiCorpVault.Internal;
using TEC.Vault.Providers;
using TEC.Vault.Providers.Http;
using TEC.Core.Common.Results;

namespace TEC.Vault.HashiCorpVault;

/// <summary>
/// Certificados no HashiCorp Vault: guardados no KV v2 em dois itens por certificado, a parte pública em <c>Kv.CertificatesPath</c>
/// (uma versão do KV por versão do certificado: DER, cadeia e exportável) e a chave privada em <c>Kv.CertificateKeysPath</c>
/// (PKCS#12 com a cadeia); emitidos pelo PKI (<c>{Pki.Mount}/sign/{Pki.Role}</c>) ou autoassinados.
/// </summary>
/// <remarks>
/// <para><b>Chave privada separada</b>: só <see cref="DownloadCertificateAsync"/> e <see cref="DownloadCertificateWithChainAsync"/>
/// leem <c>Kv.CertificateKeysPath</c> (e só depois de conferir habilitado e exportável). Leitura, listagem e gestão usam só a parte
/// pública: a política do Vault pode negar a pasta das chaves a quem não baixa certificados. Itens gravados por versões anteriores
/// (PKCS#12 no próprio item público) continuam legíveis; <see cref="MigrateCertificateKeysAsync"/> os converte.</para>
/// <para><b>Cadeia</b>: as intermediárias da importação (PFX ou PEM) e o <c>ca_chain</c> do PKI são guardados junto;
/// <see cref="DownloadCertificateWithChainAsync"/> devolve o certificado com a chave e a cadeia.</para>
/// <para><b>Emissão</b> (<see cref="CreateCertificateOptions.Issuer"/>): <c>null</c> → PKI com o emissor padrão do mount;
/// <c>"Self"</c> → autoassinado; outro valor → PKI com esse emissor (<c>{Pki.Mount}/issuer/{Issuer}/sign/{Pki.Role}</c>). O par de
/// chaves é gerado no processo (com o tipo e o tamanho pedidos) e só o CSR vai ao PKI. Sem <c>Pki.Role</c>, a emissão pelo PKI
/// retorna <see cref="VaultErrors.NotSupported"/>. Proteção por hardware e renovação automática não existem
/// (ambas retornam <see cref="VaultErrors.NotSupported"/>).</para>
/// <para><b>Habilitado e tags</b> valem para o certificado (todas as versões), guardados em <c>custom_metadata</c>; chaves de tag
/// começando por <c>tec.</c> são reservadas.</para>
/// <para><b>Lixeira</b>: como em <see cref="HashiCorpVaultSecretStore"/> (exclusão lógica das versões no KV).</para>
/// </remarks>
public sealed class HashiCorpVaultCertificateStore : HashiCorpVaultStoreBase, ICertificateStore, ICertificateRecycleBin, IVaultHealthProbe
{
    /// <summary>Valor de <see cref="CreateCertificateOptions.Issuer"/> para certificado autoassinado.</summary>
    public const string SelfIssuer = "Self";

    private const string ReservedPrefix = "tec.";
    private const string DisabledKey = "tec.disabled";
    private const string CerField = "cer";
    private const string ChainField = "chain";
    private const string Pkcs12Field = "pkcs12";
    private const string ExportableField = "exportable";
    private const string KeyVersionField = "key_version";

    /// <summary>Cria o store com conexão própria. As opções são validadas aqui.</summary>
    /// <exception cref="InvalidOperationException">Opções inválidas.</exception>
    public HashiCorpVaultCertificateStore(HashiCorpVaultOptions options, ILogger<HashiCorpVaultCertificateStore>? logger = null)
        : this(new HashiCorpVaultClient(options), ownsClient: true, logger)
    {
    }

    internal HashiCorpVaultCertificateStore(HashiCorpVaultClient client, bool ownsClient, ILogger<HashiCorpVaultCertificateStore>? logger)
        : base(client, ownsClient, logger)
    {
    }

    private KvFolder Kv => Client.Certificates;

    private KvFolder Keys => Client.CertificateKeys;

    // ---------- Criação e importação ----------

    /// <inheritdoc />
    public Task<Result<VaultCertificate>> CreateCertificateAsync(string name, CreateCertificateOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        var inputError = VaultInputRules.First(Rules.Name(name), VaultCertificateRules.Create(options), Rules.Tags(options.Tags), ReservedTags(options.Tags));

        return ExecuteAsync("certificate.create", name, inputError, isWrite: true, async ct =>
        {
            if (options.HardwareProtected || options.AutoRenewDaysBeforeExpiry is not null)
                return VaultErrors.NotSupported();   // sem HSM e sem renovação automática no Vault

            var now = Time.GetUtcNow();
            if (string.Equals(options.Issuer, SelfIssuer, StringComparison.OrdinalIgnoreCase))
            {
                using var selfSigned = VaultCertificateFactory.CreateSelfSigned(options, now);
                return await StoreAsync(name, selfSigned, [], options.Exportable, options.Enabled, options.Tags, ct).ConfigureAwait(false);
            }

            if (Client.Options.Pki.Role is not { } role)
                return VaultErrors.NotSupported();

            var (request, key) = VaultCertificateFactory.CreateRequest(options);
            using (key)
            {
                var commonName = CommonName(request.SubjectName) ?? options.DnsNames?.FirstOrDefault();
                if (commonName is null)
                    return VaultErrors.InvalidInput("subject", "O PKI exige CN no subject ou ao menos um nome DNS.");

                var hours = Math.Ceiling((now.AddMonths(options.ValidityInMonths) - now).TotalHours);
                var body = HashiCorpVaultClient.Json(w =>
                {
                    w.WriteString("csr", request.CreateSigningRequestPem());
                    w.WriteString("common_name", commonName);
                    if (options.DnsNames is { Count: > 0 } dns)
                        w.WriteString("alt_names", string.Join(',', dns));
                    w.WriteString("ttl", hours.ToString(System.Globalization.CultureInfo.InvariantCulture) + "h");
                    w.WriteString("format", "pem");
                });

                var pki = VaultEndpoint.Path(Client.Options.Pki.Mount);
                var path = options.Issuer is null
                    ? HashiCorpVaultClient.Path(pki, "sign", VaultEndpoint.Segment(role))
                    : HashiCorpVaultClient.Path(pki, "issuer", VaultEndpoint.Segment(options.Issuer), "sign", VaultEndpoint.Segment(role));

                string pem;
                List<string> chainPem;
                using (var response = await Client.SendAsync(HttpMethod.Post, path, body, idempotent: false, ct).ConfigureAwait(false))
                {
                    pem = VaultJson.String(response!.Data, "certificate") ?? throw new System.Text.Json.JsonException("Resposta do PKI sem certificado.");
                    chainPem = IssuerChain(response.Data);
                }

                using var issued = X509Certificate2.CreateFromPem(pem);
                using var withKey = VaultCertificateFactory.WithPrivateKey(issued, key);
                var chain = chainPem.Select(c => X509Certificate2.CreateFromPem(c)).ToList();
                try
                {
                    return await StoreAsync(name, withKey, chain, options.Exportable, options.Enabled, options.Tags, ct).ConfigureAwait(false);
                }
                finally
                {
                    chain.ForEach(c => c.Dispose());
                }
            }
        }, cancellationToken);
    }

    /// <inheritdoc />
    public Task<Result<VaultCertificate>> ImportCertificateAsync(string name, byte[] certificate, ImportCertificateOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        options ??= new ImportCertificateOptions();
        var inputError = Rules.ImportCertificate(name, certificate, options, out var format, out _) ?? ReservedTags(options.Tags);

        return ExecuteAsync("certificate.import", name, inputError, isWrite: true, async ct =>
        {
            // Já conferido por InspectImport: formato, senha, chave privada e tamanho da chave. A cadeia (intermediárias) que vier
            // junto é guardada com o certificado
            var all = format == CertificateContentFormat.Pem
                ? VaultCertificateRules.LoadPemCertificates(certificate)
                : VaultCertificateLoader.LoadPkcs12Collection(certificate, options.Password, VaultCertificateLoader.SafeKeyStorageFlags | X509KeyStorageFlags.Exportable);
            try
            {
                if (format == CertificateContentFormat.Pem)
                {
                    using var leaf = VaultCertificateRules.LoadPem(certificate, options.Password);
                    return await StoreAsync(name, leaf, Others(all, leaf), options.Exportable, options.Enabled, options.Tags, ct).ConfigureAwait(false);
                }

                var withKey = all.FirstOrDefault(c => c.HasPrivateKey) ?? throw new CryptographicException("PKCS#12 sem chave privada.");
                return await StoreAsync(name, withKey, Others(all, withKey), options.Exportable, options.Enabled, options.Tags, ct).ConfigureAwait(false);
            }
            finally
            {
                foreach (var item in all)
                    item.Dispose();
            }
        }, cancellationToken);
    }

    // ---------- Leitura ----------

    /// <inheritdoc />
    public Task<Result<VaultCertificate>> GetCertificateAsync(string name, string? version = null, CancellationToken cancellationToken = default) =>
        ExecuteAsync("certificate.get", name, Rules.Item(name, version), isWrite: false, async ct =>
        {
            var item = await ReadAsync(name, version, ct).ConfigureAwait(false);
            if (item.Error is not null)
                return item.Error;
            var (metadata, fields, number, createdOn) = item.Value!.Value;
            CryptographicOperations.ZeroMemory(Pkcs12(fields));   // só a parte pública é devolvida
            var cer = Convert.FromBase64String(fields[CerField]);
            return Result<VaultCertificate>.Success(new VaultCertificate { Properties = Properties(metadata, number, createdOn, cer), Cer = cer });
        }, cancellationToken);

    /// <inheritdoc />
    /// <remarks>
    /// Auditado como escrita: é a operação que tira a chave privada do cofre. Só certificados exportáveis e habilitados; a pasta das
    /// chaves (<c>Kv.CertificateKeysPath</c>) só é lida depois dessas conferências. Para receber também a cadeia, use
    /// <see cref="DownloadCertificateWithChainAsync"/>.
    /// </remarks>
    public Task<Result<X509Certificate2>> DownloadCertificateAsync(string name, string? version = null, CancellationToken cancellationToken = default) =>
        ExecuteAsync<X509Certificate2>("certificate.download", name, Rules.Item(name, version), isWrite: true, async ct =>
        {
            var pkcs12 = await PrivateMaterialAsync(name, version, ct).ConfigureAwait(false);
            if (pkcs12.Error is not null)
                return pkcs12.Error;
            try
            {
                return VaultCertificateLoader.LoadPkcs12(pkcs12.Value!, password: null);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pkcs12.Value);
            }
        }, cancellationToken);

    /// <summary>
    /// Baixa o certificado com a chave privada e a cadeia guardada com ele (intermediárias da importação ou o <c>ca_chain</c> do PKI),
    /// para uso em TLS de servidor. Mesmas regras de <see cref="DownloadCertificateAsync"/> (auditado como escrita; só exportável e
    /// habilitado).
    /// </summary>
    /// <param name="name">Nome do certificado.</param>
    /// <param name="version">Versão. <c>null</c> = atual.</param>
    /// <param name="cancellationToken">Cancelamento.</param>
    /// <returns>
    /// Coleção com o certificado com a chave privada <b>primeiro</b>, seguido da cadeia (vazia para certificados autoassinados e para
    /// itens gravados antes da versão 0.2.0). O chamador descarta cada certificado.
    /// </returns>
    public Task<Result<X509Certificate2Collection>> DownloadCertificateWithChainAsync(string name, string? version = null,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync<X509Certificate2Collection>("certificate.download", name, Rules.Item(name, version), isWrite: true, async ct =>
        {
            var pkcs12 = await PrivateMaterialAsync(name, version, ct).ConfigureAwait(false);
            if (pkcs12.Error is not null)
                return pkcs12.Error;
            try
            {
                var all = VaultCertificateLoader.LoadPkcs12Collection(pkcs12.Value!, password: null);
                var ordered = new X509Certificate2Collection();
                ordered.AddRange(all.Where(c => c.HasPrivateKey).ToArray());
                ordered.AddRange(all.Where(c => !c.HasPrivateKey).ToArray());
                return ordered;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pkcs12.Value);
            }
        }, cancellationToken);

    /// <summary>
    /// Converte um certificado gravado por versões anteriores à 0.2.0 (PKCS#12 no item público, legível por quem só tem <c>read</c> em
    /// <c>Kv.CertificatesPath</c>) para o formato com a chave privada em <c>Kv.CertificateKeysPath</c>.
    /// </summary>
    /// <remarks>
    /// <para>Se a versão atual está no formato antigo, grava a chave privada na pasta das chaves e uma nova versão pública (mesmo
    /// certificado, mesmo exportável; o número da versão avança). Depois <b>destrói</b> (definitivo) as versões anteriores do item
    /// público que ainda guardam o PKCS#12: as ativas que estão no formato antigo e, se a atual era do formato antigo, também as que
    /// estão na lixeira (não legíveis para conferir). Versões anteriores já no formato novo são mantidas.</para>
    /// <para>Idempotente: um certificado já convertido retorna <c>false</c> sem gravar nada. Exige, além da política de escrita dos
    /// certificados, <c>update</c> em <c>{Kv.Mount}/destroy/...</c>. Auditado como escrita.</para>
    /// </remarks>
    /// <param name="name">Nome do certificado.</param>
    /// <param name="cancellationToken">Cancelamento.</param>
    /// <returns><c>true</c> se algo foi convertido ou destruído; <c>false</c> se já estava no formato novo.</returns>
    public Task<Result<bool>> MigrateCertificateKeysAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync("certificate.migrate", name, Rules.Name(name), isWrite: true, async ct =>
        {
            var (metadata, ambiguous) = await Kv.ResolveAsync(name, ct).ConfigureAwait(false);
            if (ambiguous)
                return VaultErrors.Conflict();
            if (metadata is not { Exists: true })
                return VaultErrors.NotFound();
            if (await Kv.ReadAsync(metadata.Name, metadata.CurrentVersion, ct).ConfigureAwait(false) is not { } current ||
                !current.Fields.TryGetValue(CerField, out var cer))
                throw new System.Text.Json.JsonException("Item do KV sem os campos do certificado.");

            var changed = false;
            var currentIsLegacy = current.Fields.ContainsKey(Pkcs12Field);
            var keep = current.Version;
            if (currentIsLegacy)
            {
                var fields = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    [CerField] = cer,
                    [ExportableField] = current.Fields.GetValueOrDefault(ExportableField) ?? "false"
                };
                keep = (await WriteBothAsync(metadata.Name, current.Fields[Pkcs12Field], fields, ct).ConfigureAwait(false)).Version;
                changed = true;
            }

            var destroy = new List<int>();
            foreach (var version in metadata.Versions.Where(v => v.Version < keep && !v.Destroyed))
            {
                if (!version.Alive)
                {
                    if (currentIsLegacy)
                        destroy.Add(version.Version);
                }
                else if (await Kv.ReadAsync(metadata.Name, version.Version, ct).ConfigureAwait(false) is { } old && old.Fields.ContainsKey(Pkcs12Field))
                {
                    destroy.Add(version.Version);
                }
            }

            if (destroy.Count > 0)
            {
                await Kv.DestroyVersionsAsync(metadata.Name, destroy, ct).ConfigureAwait(false);
                changed = true;
            }

            return Result<bool>.Success(changed);
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<CertificateProperties>>> ListCertificatesAsync(CancellationToken cancellationToken = default) =>
        ExecuteAsync<IReadOnlyList<CertificateProperties>>("certificate.list", null, null, isWrite: false, async ct =>
        {
            var result = new List<CertificateProperties>();
            var names = await Kv.ListAsync(ct).ConfigureAwait(false);
            EnsureListLimit(names.Count, Client.Options.MaxListItems);
            foreach (var name in names)
            {
                if (Rules.Name(name) is not null || await Kv.MetadataAsync(name, ct).ConfigureAwait(false) is not { Exists: true } metadata)
                    continue;
                if (await PropertiesAsync(metadata, metadata.CurrentVersion, ct).ConfigureAwait(false) is { } properties)
                    result.Add(properties);
            }

            return result;
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<CertificateProperties>>> ListCertificateVersionsAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync("certificate.versions", name, Rules.Name(name), isWrite: false, async ct =>
        {
            var (metadata, ambiguous) = await Kv.ResolveAsync(name, ct).ConfigureAwait(false);
            if (ambiguous)
                return VaultErrors.Conflict();
            if (metadata is not { Exists: true })
                return VaultErrors.NotFound();

            // Uma leitura por versão: o limite é conferido antes de ler qualquer uma
            EnsureListLimit(metadata.Versions.Count(v => v.Alive), Client.Options.MaxListItems);
            var result = new List<CertificateProperties>();
            foreach (var version in metadata.Versions.Where(v => v.Alive))
            {
                if (await PropertiesAsync(metadata, version.Version, ct).ConfigureAwait(false) is { } properties)
                    result.Add(properties);
            }

            return Result<IReadOnlyList<CertificateProperties>>.Success(result);
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result> CheckAccessAsync(CancellationToken cancellationToken = default) =>
        RunAsync("certificate.health", null, null, isWrite: false, async ct =>
        {
            await Kv.ListAsync(ct).ConfigureAwait(false);
            return Result.Success();
        }, cancellationToken);

    // ---------- Gestão ----------

    /// <inheritdoc />
    /// <remarks>Habilitado e tags valem para o certificado inteiro: <paramref name="version"/> só é conferida.</remarks>
    public Task<Result<CertificateProperties>> UpdateCertificatePropertiesAsync(string name, CertificatePropertiesUpdate update,
        string? version = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(update);
        var inputError = VaultInputRules.First(Rules.Name(name), Rules.Version(version), Rules.Tags(update.Tags), ReservedTags(update.Tags));

        return ExecuteAsync("certificate.update", name, inputError, isWrite: true, async ct =>
        {
            var (metadata, ambiguous) = await Kv.ResolveAsync(name, ct).ConfigureAwait(false);
            if (ambiguous)
                return VaultErrors.Conflict();
            if (metadata is not { Exists: true })
                return VaultErrors.NotFound();
            var number = ParseVersion(version) ?? metadata.CurrentVersion;
            if (metadata.Versions.FirstOrDefault(v => v.Version == number) is not { Alive: true })
                return VaultErrors.NotFound();

            var custom = Custom(update.Tags ?? UserTags(metadata.Custom), update.Enabled ?? !metadata.Custom.ContainsKey(DisabledKey));
            await Kv.SetCustomMetadataAsync(metadata.Name, custom, ct).ConfigureAwait(false);
            var properties = await PropertiesAsync(metadata with { Custom = custom }, number, ct).ConfigureAwait(false);
            return properties is null ? VaultErrors.NotFound() : Result<CertificateProperties>.Success(properties);
        }, cancellationToken);
    }

    /// <inheritdoc />
    public Task<Result<DeletedVaultItem>> DeleteCertificateAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync("certificate.delete", name, Rules.Name(name), isWrite: true, async ct =>
        {
            var (metadata, ambiguous) = await Kv.ResolveAsync(name, ct).ConfigureAwait(false);
            if (ambiguous)
                return VaultErrors.Conflict();
            if (metadata is null || !metadata.Versions.Any(v => v.Alive))
                return VaultErrors.NotFound();

            // Chaves privadas primeiro: uma falha no meio nunca deixa a chave ativa com o certificado já na lixeira
            if (await Keys.MetadataAsync(metadata.Name, ct).ConfigureAwait(false) is { } keys)
                await Keys.DeleteVersionsAsync(metadata.Name, keys.Versions.Where(v => v.Alive).Select(v => v.Version), ct).ConfigureAwait(false);
            await Kv.DeleteVersionsAsync(metadata.Name, metadata.Versions.Where(v => v.Alive).Select(v => v.Version), ct).ConfigureAwait(false);
            return Result<DeletedVaultItem>.Success(new DeletedVaultItem(metadata.Name, Time.GetUtcNow(), ScheduledPurgeDate: null));
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<DeletedVaultItem>>> ListDeletedCertificatesAsync(CancellationToken cancellationToken = default) =>
        ExecuteAsync<IReadOnlyList<DeletedVaultItem>>("certificate.list-deleted", null, null, isWrite: false, async ct =>
        {
            var result = new List<DeletedVaultItem>();
            var names = await Kv.ListAsync(ct).ConfigureAwait(false);
            EnsureListLimit(names.Count, Client.Options.MaxListItems);
            foreach (var name in names)
            {
                if (await Kv.MetadataAsync(name, ct).ConfigureAwait(false) is { IsDeleted: true } metadata)
                    result.Add(new DeletedVaultItem(metadata.Name, metadata.Versions.Max(v => v.DeletedOn), ScheduledPurgeDate: null));
            }

            return result;
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<VaultCertificate>> RecoverDeletedCertificateAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync("certificate.recover", name, Rules.Name(name), isWrite: true, async ct =>
        {
            var (metadata, ambiguous) = await Kv.ResolveAsync(name, ct).ConfigureAwait(false);
            if (ambiguous)
                return VaultErrors.Conflict();
            if (metadata is not { IsDeleted: true })
                return VaultErrors.NotFound();

            await Kv.UndeleteAsync(metadata.Name, metadata.Versions.Where(v => v.DeletedOn is not null && !v.Destroyed).Select(v => v.Version), ct)
                .ConfigureAwait(false);
            if (await Keys.MetadataAsync(metadata.Name, ct).ConfigureAwait(false) is { } keys)
            {
                await Keys.UndeleteAsync(metadata.Name, keys.Versions.Where(v => v.DeletedOn is not null && !v.Destroyed).Select(v => v.Version), ct)
                    .ConfigureAwait(false);
            }

            var item = await ReadAsync(metadata.Name, null, ct).ConfigureAwait(false);
            if (item.Error is not null)
                return item.Error;
            var (current, fields, number, createdOn) = item.Value!.Value;
            CryptographicOperations.ZeroMemory(Pkcs12(fields));
            var cer = Convert.FromBase64String(fields[CerField]);
            return Result<VaultCertificate>.Success(new VaultCertificate { Properties = Properties(current, number, createdOn, cer), Cer = cer });
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result> PurgeDeletedCertificateAsync(string name, CancellationToken cancellationToken = default) =>
        RunAsync("certificate.purge", name, Rules.Name(name), isWrite: true, async ct =>
        {
            var (metadata, ambiguous) = await Kv.ResolveAsync(name, ct).ConfigureAwait(false);
            if (ambiguous)
                return Result.Failure(VaultErrors.Conflict());
            if (metadata is not { IsDeleted: true })
                return Result.Failure(VaultErrors.NotFound());

            if (await Keys.MetadataAsync(metadata.Name, ct).ConfigureAwait(false) is not null)
                await Keys.DestroyAsync(metadata.Name, ct).ConfigureAwait(false);
            await Kv.DestroyAsync(metadata.Name, ct).ConfigureAwait(false);
            return Result.Success();
        }, cancellationToken);

    // ---------- Implementação ----------

    private async Task<Result<VaultCertificate>> StoreAsync(string name, X509Certificate2 certificate, IReadOnlyList<X509Certificate2> chain,
        bool exportable, bool enabled, IReadOnlyDictionary<string, string>? tags, CancellationToken ct)
    {
        var (metadata, ambiguous) = await Kv.ResolveAsync(name, ct).ConfigureAwait(false);
        if (ambiguous || metadata is { IsDeleted: true })
            return VaultErrors.Conflict();

        var target = metadata?.Name ?? name;

        // PKCS#12 (sem senha: protegido pela política da pasta das chaves) com o certificado, a chave e a cadeia
        var collection = new X509Certificate2Collection(certificate);
        foreach (var intermediate in chain)
            collection.Add(intermediate);
        var pkcs12 = collection.Export(X509ContentType.Pkcs12) ?? throw new CryptographicException("Falha ao exportar o PKCS#12.");
        var pkcs12Text = Convert.ToBase64String(pkcs12);
        CryptographicOperations.ZeroMemory(pkcs12);
        var cer = certificate.RawData;

        var fields = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [CerField] = Convert.ToBase64String(cer),
            [ExportableField] = exportable ? "true" : "false"
        };
        if (chain.Count > 0)
            fields[ChainField] = string.Join(',', chain.Select(c => Convert.ToBase64String(c.RawData)));
        var written = await WriteBothAsync(target, pkcs12Text, fields, ct).ConfigureAwait(false);

        var custom = Custom(tags ?? new Dictionary<string, string>(), enabled);
        await Kv.SetCustomMetadataAsync(target, custom, ct).ConfigureAwait(false);

        var properties = Properties(new KvMetadata(target, written.Version, [], custom, written.CreatedOn, written.CreatedOn),
            written.Version, written.CreatedOn, cer);
        return Result<VaultCertificate>.Success(new VaultCertificate { Properties = properties, Cer = cer });
    }

    /// <summary>
    /// Grava a chave privada (pasta das chaves) e depois a parte pública, que aponta para a versão da chave. Se a parte pública
    /// falhar, a versão da chave recém-gravada é destruída (melhor esforço): sem certificado, ela não seria alcançável.
    /// </summary>
    private async Task<(int Version, DateTimeOffset? CreatedOn)> WriteBothAsync(string target, string pkcs12Text, Dictionary<string, string> fields,
        CancellationToken ct)
    {
        var key = await Keys.WriteAsync(target, new Dictionary<string, string> { [Pkcs12Field] = pkcs12Text }, ct).ConfigureAwait(false);
        fields[KeyVersionField] = Text(key.Version);
        try
        {
            return await Kv.WriteAsync(target, fields, ct).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is VaultHttpException or HttpRequestException or TimeoutException or OperationCanceledException)
        {
            try
            {
                await Keys.DestroyVersionsAsync(target, [key.Version], CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception cleanup) when (cleanup is VaultHttpException or HttpRequestException or TimeoutException or OperationCanceledException)
            {
                // A falha original é a que importa; a versão órfã continua protegida pela política da pasta das chaves
            }

            throw;
        }
    }

    /// <summary>
    /// PKCS#12 da versão pedida, só se habilitado e exportável (o chamador zera). No formato novo lê a pasta das chaves na versão
    /// apontada pelo item público; no antigo, o campo do próprio item.
    /// </summary>
    private async Task<(Error? Error, byte[]? Value)> PrivateMaterialAsync(string name, string? version, CancellationToken ct)
    {
        var item = await ReadAsync(name, version, ct).ConfigureAwait(false);
        if (item.Error is not null)
            return (item.Error, null);
        var (metadata, fields, _, _) = item.Value!.Value;
        if (metadata.Custom.ContainsKey(DisabledKey))
            return (VaultErrors.Disabled(), null);
        if (!string.Equals(fields.GetValueOrDefault(ExportableField), "true", StringComparison.Ordinal))
            return (VaultErrors.NotExportable(), null);

        if (!fields.TryGetValue(KeyVersionField, out var keyVersion))
            return (null, Pkcs12(fields));   // formato anterior à 0.2.0

        if (!int.TryParse(keyVersion, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var number) ||
            number < 1)
            throw new System.Text.Json.JsonException("Item do KV com key_version inválido.");
        var key = await Keys.ReadAsync(metadata.Name, number, ct).ConfigureAwait(false);
        if (key is not { } read || !read.Fields.ContainsKey(Pkcs12Field))
            return (VaultErrors.NotFound(), null);   // chave excluída ou destruída
        return (null, Pkcs12(read.Fields));
    }

    private async Task<(Error? Error, (KvMetadata Metadata, Dictionary<string, string> Fields, int Version, DateTimeOffset? CreatedOn)? Value)> ReadAsync(
        string name, string? version, CancellationToken ct)
    {
        var (metadata, ambiguous) = await Kv.ResolveAsync(name, ct).ConfigureAwait(false);
        if (ambiguous)
            return (VaultErrors.Conflict(), null);
        if (metadata is null || (!metadata.Exists && version is null))
            return (VaultErrors.NotFound(), null);

        var item = await Kv.ReadAsync(metadata.Name, ParseVersion(version), ct).ConfigureAwait(false);
        if (item is not { } read)
            return (VaultErrors.NotFound(), null);
        if (!read.Fields.ContainsKey(CerField) || !(read.Fields.ContainsKey(KeyVersionField) || read.Fields.ContainsKey(Pkcs12Field)))
            throw new System.Text.Json.JsonException("Item do KV sem os campos do certificado.");
        return (null, (metadata, read.Fields, read.Version, read.CreatedOn));
    }

    private async Task<CertificateProperties?> PropertiesAsync(KvMetadata metadata, int version, CancellationToken ct)
    {
        var item = await Kv.ReadAsync(metadata.Name, version, ct).ConfigureAwait(false);
        if (item is not { } read || !read.Fields.TryGetValue(CerField, out var cer))
            return null;
        CryptographicOperations.ZeroMemory(Pkcs12(read.Fields));
        return Properties(metadata, read.Version, read.CreatedOn, Convert.FromBase64String(cer));
    }

    private CertificateProperties Properties(KvMetadata metadata, int version, DateTimeOffset? createdOn, byte[] cer)
    {
        using var certificate = VaultCertificateLoader.LoadCertificate(cer);
        return new CertificateProperties
        {
            Name = metadata.Name,
            Version = Text(version),
            Id = Kv.Id(metadata.Name),
            Enabled = !metadata.Custom.ContainsKey(DisabledKey),
            CreatedOn = createdOn,
            UpdatedOn = metadata.UpdatedOn ?? createdOn,
            NotBefore = new DateTimeOffset(certificate.NotBefore.ToUniversalTime(), TimeSpan.Zero),
            ExpiresOn = new DateTimeOffset(certificate.NotAfter.ToUniversalTime(), TimeSpan.Zero),
            Thumbprint = certificate.Thumbprint,
            Tags = UserTags(metadata.Custom)
        };
    }

    /// <summary>PKCS#12 decodificado (o chamador zera).</summary>
    private static byte[] Pkcs12(Dictionary<string, string> fields) =>
        fields.TryGetValue(Pkcs12Field, out var text) ? Convert.FromBase64String(text) : [];

    /// <summary>Certificados da coleção que não são <paramref name="leaf"/> (a cadeia).</summary>
    private static List<X509Certificate2> Others(X509Certificate2Collection all, X509Certificate2 leaf) =>
        all.Where(c => !c.RawDataMemory.Span.SequenceEqual(leaf.RawDataMemory.Span)).ToList();

    /// <summary>Cadeia do emissor na resposta do PKI: <c>ca_chain</c> ou, sem ele, <c>issuing_ca</c>.</summary>
    private static List<string> IssuerChain(System.Text.Json.JsonElement data)
    {
        var chain = new List<string>();
        if (data.TryGetProperty("ca_chain", out var array) && array.ValueKind == System.Text.Json.JsonValueKind.Array)
        {
            foreach (var item in array.EnumerateArray())
            {
                if (item.ValueKind == System.Text.Json.JsonValueKind.String && item.GetString() is { Length: > 0 } pem)
                    chain.Add(pem);
            }
        }

        if (chain.Count == 0 && VaultJson.String(data, "issuing_ca") is { Length: > 0 } issuing)
            chain.Add(issuing);
        return chain;
    }

    private static Dictionary<string, string> Custom(IReadOnlyDictionary<string, string> tags, bool enabled)
    {
        var custom = new Dictionary<string, string>(tags, StringComparer.Ordinal);
        if (!enabled)
            custom[DisabledKey] = "true";
        return custom;
    }

    private static Dictionary<string, string> UserTags(IReadOnlyDictionary<string, string> custom) =>
        custom.Where(kv => !kv.Key.StartsWith(ReservedPrefix, StringComparison.OrdinalIgnoreCase)).ToDictionary(kv => kv.Key, kv => kv.Value);

    private static Error? ReservedTags(IReadOnlyDictionary<string, string>? tags) =>
        tags is not null && tags.Keys.Any(k => k.StartsWith(ReservedPrefix, StringComparison.OrdinalIgnoreCase))
            ? VaultErrors.InvalidInput("tags", $"Chaves de tag começando por '{ReservedPrefix}' são reservadas.")
            : null;

    private static string? CommonName(X500DistinguishedName subject)
    {
        foreach (var rdn in subject.EnumerateRelativeDistinguishedNames())
        {
            if (!rdn.HasMultipleElements && rdn.GetSingleElementType().Value == "2.5.4.3")
                return rdn.GetSingleElementValue();
        }

        return null;
    }
}
