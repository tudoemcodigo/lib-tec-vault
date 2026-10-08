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
/// Certificados no HashiCorp Vault: guardados no KV v2 (pasta <c>Kv.CertificatesPath</c>, uma versão do KV por versão do
/// certificado, com o PKCS#12) e emitidos pelo PKI (<c>{Pki.Mount}/sign/{Pki.Role}</c>) ou autoassinados.
/// </summary>
/// <remarks>
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
    private const string Pkcs12Field = "pkcs12";
    private const string ExportableField = "exportable";

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
                return await StoreAsync(name, selfSigned, options.Exportable, options.Enabled, options.Tags, ct).ConfigureAwait(false);
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
                using (var response = await Client.SendAsync(HttpMethod.Post, path, body, idempotent: false, ct).ConfigureAwait(false))
                    pem = VaultJson.String(response!.Data, "certificate") ?? throw new System.Text.Json.JsonException("Resposta do PKI sem certificado.");

                using var issued = X509Certificate2.CreateFromPem(pem);
                using var withKey = VaultCertificateFactory.WithPrivateKey(issued, key);
                return await StoreAsync(name, withKey, options.Exportable, options.Enabled, options.Tags, ct).ConfigureAwait(false);
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
            // Já conferido por InspectImport: formato, senha, chave privada e tamanho da chave
            using var loaded = format == CertificateContentFormat.Pem
                ? VaultCertificateRules.LoadPem(certificate, options.Password)
                : VaultCertificateLoader.LoadPkcs12(certificate, options.Password, VaultCertificateLoader.SafeKeyStorageFlags | X509KeyStorageFlags.Exportable);
            return await StoreAsync(name, loaded, options.Exportable, options.Enabled, options.Tags, ct).ConfigureAwait(false);
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
    /// <remarks>Auditado como escrita: é a operação que tira a chave privada do cofre. Só certificados exportáveis e habilitados.</remarks>
    public Task<Result<X509Certificate2>> DownloadCertificateAsync(string name, string? version = null, CancellationToken cancellationToken = default) =>
        ExecuteAsync<X509Certificate2>("certificate.download", name, Rules.Item(name, version), isWrite: true, async ct =>
        {
            var item = await ReadAsync(name, version, ct).ConfigureAwait(false);
            if (item.Error is not null)
                return item.Error;
            var (metadata, fields, _, _) = item.Value!.Value;
            var pkcs12 = Pkcs12(fields);
            try
            {
                if (metadata.Custom.ContainsKey(DisabledKey))
                    return VaultErrors.Disabled();
                if (!string.Equals(fields.GetValueOrDefault(ExportableField), "true", StringComparison.Ordinal))
                    return VaultErrors.NotExportable();
                return VaultCertificateLoader.LoadPkcs12(pkcs12, password: null);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pkcs12);
            }
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

            await Kv.DestroyAsync(metadata.Name, ct).ConfigureAwait(false);
            return Result.Success();
        }, cancellationToken);

    // ---------- Implementação ----------

    private async Task<Result<VaultCertificate>> StoreAsync(string name, X509Certificate2 certificate, bool exportable, bool enabled,
        IReadOnlyDictionary<string, string>? tags, CancellationToken ct)
    {
        var (metadata, ambiguous) = await Kv.ResolveAsync(name, ct).ConfigureAwait(false);
        if (ambiguous || metadata is { IsDeleted: true })
            return VaultErrors.Conflict();

        var target = metadata?.Name ?? name;
        var pkcs12 = certificate.Export(X509ContentType.Pkcs12);
        var pkcs12Text = Convert.ToBase64String(pkcs12);
        CryptographicOperations.ZeroMemory(pkcs12);
        var cer = certificate.RawData;

        var written = await Kv.WriteAsync(target, new Dictionary<string, string>
        {
            [CerField] = Convert.ToBase64String(cer),
            [Pkcs12Field] = pkcs12Text,
            [ExportableField] = exportable ? "true" : "false"
        }, ct).ConfigureAwait(false);

        var custom = Custom(tags ?? new Dictionary<string, string>(), enabled);
        await Kv.SetCustomMetadataAsync(target, custom, ct).ConfigureAwait(false);

        var properties = Properties(new KvMetadata(target, written.Version, [], custom, written.CreatedOn, written.CreatedOn),
            written.Version, written.CreatedOn, cer);
        return Result<VaultCertificate>.Success(new VaultCertificate { Properties = properties, Cer = cer });
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
        if (!read.Fields.ContainsKey(CerField) || !read.Fields.ContainsKey(Pkcs12Field))
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
