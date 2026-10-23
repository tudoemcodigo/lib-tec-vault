using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using Azure.Security.KeyVault.Certificates;
using Microsoft.Extensions.Logging;
using TEC.Vault.Abstractions;
using TEC.Vault.AzureKeyVault.Internal;
using TEC.Vault.Certificates;
using TEC.Vault.Common;
using TEC.Vault.Keys;
using TEC.Vault.Providers;
using TEC.Core.Common.Results;
using AzCertificateProperties = Azure.Security.KeyVault.Certificates.CertificateProperties;
using AzImportCertificateOptions = Azure.Security.KeyVault.Certificates.ImportCertificateOptions;
using CertificateProperties = TEC.Vault.Certificates.CertificateProperties;
using ImportCertificateOptions = TEC.Vault.Certificates.ImportCertificateOptions;

namespace TEC.Vault.AzureKeyVault;

/// <summary>
/// Certificados do Azure Key Vault: leitura, gestão, lixeira e backup. Permissões RBAC: gerenciamento "Key Vault Certificates Officer";
/// download com chave privada exige também "Key Vault Secrets User". Crie com <c>UseAzureKeyVault</c> (DI) ou <see cref="AzureKeyVaultStores"/>.
/// </summary>
/// <remarks>
/// O Key Vault cria, junto com cada certificado, uma chave e um segredo com o mesmo nome, gerenciados por ele
/// (<see cref="VaultItemProperties.ManagedBy"/> = <c>"certificate"</c>): a chave pode ser usada por <see cref="IKeyCryptography"/>
/// para assinar sem que a chave privada saia do cofre.
/// </remarks>
public sealed partial class AzureKeyVaultCertificateStore : AzureKeyVaultStoreBase, ICertificateStore, ICertificateRecycleBin, ICertificateBackup, IVaultHealthProbe
{
    internal AzureKeyVaultCertificateStore(AzureKeyVaultClients clients, ILogger<AzureKeyVaultCertificateStore>? logger = null)
        : base(clients, logger)
    {
    }

    private CertificateClient Client => Clients.Certificates;

    /// <summary>Emissor do Key Vault usado quando <see cref="CreateCertificateOptions.Issuer"/> é <c>null</c>: autoassinado.</summary>
    internal const string SelfIssuer = "Self";

    /// <inheritdoc />
    public Task<Result<VaultCertificate>> CreateCertificateAsync(string name, CreateCertificateOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        var inputError = VaultInputRules.First(Rules.Name(name), ValidateCreate(options), Rules.Tags(options.Tags));

        return ExecuteAsync<VaultCertificate>("certificate.create", name, inputError, isWrite: true, async ct =>
        {
            var policy = BuildPolicy(options);
            using var timeout = WithOperationTimeout(ct);
            var operation = await Client.StartCreateCertificateAsync(name, policy, options.Enabled,
                options.Tags is null ? null : new Dictionary<string, string>(options.Tags, StringComparer.Ordinal), timeout.Token).ConfigureAwait(false);
            KeyVaultCertificateWithPolicy certificate = await operation.WaitForCompletionAsync(timeout.Token).ConfigureAwait(false);
            return ToModel(certificate);
        }, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<Result<VaultCertificate>> ImportCertificateAsync(string name, byte[] certificate, ImportCertificateOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        options ??= new ImportCertificateOptions();
        var inputError = Rules.ImportCertificate(name, certificate, options, out var format, out string? subject);

        // PEM: envia só os blocos PEM (sem "Bag Attributes" e outros textos que o OpenSSL coloca entre eles)
        byte[] content = inputError is null && format == CertificateContentFormat.Pem ? VaultCertificateRules.NormalizePem(certificate) : certificate;
        try
        {
            return await ExecuteAsync<VaultCertificate>("certificate.import", name, inputError, isWrite: true, async ct =>
            {
                var import = new AzImportCertificateOptions(name, content)
                {
                    Password = options.Password,
                    Enabled = options.Enabled,
                    Policy = new CertificatePolicy(WellKnownIssuerNames.Unknown, subject!)
                    {
                        ContentType = format == CertificateContentFormat.Pem ? CertificateContentType.Pem : CertificateContentType.Pkcs12,
                        Exportable = options.Exportable
                    }
                };
                ReplaceTags(import.Tags, options.Tags);

                KeyVaultCertificateWithPolicy imported = await Client.ImportCertificateAsync(import, ct).ConfigureAwait(false);
                return ToModel(imported);
            }, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            // A cópia normalizada (com a chave privada) é desta biblioteca: zerada após o envio. O array do chamador não é tocado
            if (!ReferenceEquals(content, certificate))
                CryptographicOperations.ZeroMemory(content);
        }
    }

    /// <inheritdoc />
    public Task<Result<VaultCertificate>> GetCertificateAsync(string name, string? version = null, CancellationToken cancellationToken = default) =>
        ExecuteAsync<VaultCertificate>("certificate.get", name, Rules.Item(name, version), isWrite: false,
            async ct => ToModel(await GetAzureCertificateAsync(name, version, ct).ConfigureAwait(false)), cancellationToken);

    /// <inheritdoc />
    public Task<Result<X509Certificate2>> DownloadCertificateAsync(string name, string? version = null, CancellationToken cancellationToken = default) =>
        ExecuteAsync<X509Certificate2>("certificate.download", name, Rules.Item(name, version),
            // Auditado como escrita: é a única operação que tira uma chave privada do cofre
            isWrite: true, async ct =>
            {
                var download = new DownloadCertificateOptions(name) { Version = version, KeyStorageFlags = VaultCertificateLoader.SafeKeyStorageFlags };
                X509Certificate2 certificate = await Client.DownloadCertificateAsync(download, ct).ConfigureAwait(false);
                if (certificate.HasPrivateKey)
                    return certificate;

                certificate.Dispose();
                return VaultErrors.NotExportable();
            }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<CertificateProperties>>> ListCertificatesAsync(CancellationToken cancellationToken = default) =>
        ExecuteAsync<IReadOnlyList<CertificateProperties>>("certificate.list", null, null, isWrite: false, async ct =>
        {
            var list = new List<CertificateProperties>();
            await foreach (var properties in Client.GetPropertiesOfCertificatesAsync(includePending: false, ct).ConfigureAwait(false))
            {
                EnsureListLimit(list.Count + 1, Clients.MaxListItems);
                list.Add(ToModel(properties));
            }
            return list;
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<CertificateProperties>>> ListCertificateVersionsAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync<IReadOnlyList<CertificateProperties>>("certificate.versions", name, Rules.Name(name), isWrite: false, async ct =>
        {
            var list = new List<CertificateProperties>();
            await foreach (var properties in Client.GetPropertiesOfCertificateVersionsAsync(name, ct).ConfigureAwait(false))
            {
                EnsureListLimit(list.Count + 1, Clients.MaxListItems);
                list.Add(ToModel(properties));
            }
            return list.Count == 0 ? VaultErrors.NotFound() : list;
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<CertificateProperties>> UpdateCertificatePropertiesAsync(string name, CertificatePropertiesUpdate update,
        string? version = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(update);
        return ExecuteAsync<CertificateProperties>("certificate.update", name,
            VaultInputRules.First(Rules.Name(name), Rules.Version(version), Rules.Tags(update.Tags)), isWrite: true, async ct =>
            {
                var current = await GetAzureCertificateAsync(name, version, ct).ConfigureAwait(false);
                var properties = current.Properties;
                if (update.Enabled is { } enabled) properties.Enabled = enabled;
                ReplaceTags(properties.Tags, update.Tags);

                KeyVaultCertificate updated = await Client.UpdateCertificatePropertiesAsync(properties, ct).ConfigureAwait(false);
                return ToModel(updated.Properties);
            }, cancellationToken);
    }

    /// <inheritdoc />
    public Task<Result<DeletedVaultItem>> DeleteCertificateAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync<DeletedVaultItem>("certificate.delete", name, Rules.Name(name), isWrite: true, async ct =>
        {
            using var timeout = WithOperationTimeout(ct);
            var operation = await Client.StartDeleteCertificateAsync(name, timeout.Token).ConfigureAwait(false);
            DeletedCertificate deleted = await operation.WaitForCompletionAsync(timeout.Token).ConfigureAwait(false);
            return ToDeleted(deleted.Name, deleted.DeletedOn, deleted.ScheduledPurgeDate);
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<DeletedVaultItem>>> ListDeletedCertificatesAsync(CancellationToken cancellationToken = default) =>
        ExecuteAsync<IReadOnlyList<DeletedVaultItem>>("certificate.list-deleted", null, null, isWrite: false, async ct =>
        {
            var list = new List<DeletedVaultItem>();
            await foreach (var deleted in Client.GetDeletedCertificatesAsync(includePending: false, ct).ConfigureAwait(false))
            {
                EnsureListLimit(list.Count + 1, Clients.MaxListItems);
                list.Add(ToDeleted(deleted.Name, deleted.DeletedOn, deleted.ScheduledPurgeDate));
            }
            return list;
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<VaultCertificate>> RecoverDeletedCertificateAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync<VaultCertificate>("certificate.recover", name, Rules.Name(name), isWrite: true, async ct =>
        {
            using var timeout = WithOperationTimeout(ct);
            var operation = await Client.StartRecoverDeletedCertificateAsync(name, timeout.Token).ConfigureAwait(false);
            KeyVaultCertificateWithPolicy certificate = await operation.WaitForCompletionAsync(timeout.Token).ConfigureAwait(false);
            return ToModel(certificate);
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result> PurgeDeletedCertificateAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync("certificate.purge", name, Rules.Name(name), isWrite: true,
            ct => Client.PurgeDeletedCertificateAsync(name, ct), cancellationToken);

    /// <inheritdoc />
    public Task<Result<byte[]>> BackupCertificateAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync<byte[]>("certificate.backup", name, Rules.Name(name), isWrite: true, async ct =>
        {
            byte[] backup = await Client.BackupCertificateAsync(name, ct).ConfigureAwait(false);
            return backup;
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<VaultCertificate>> RestoreCertificateBackupAsync(byte[] backup, CancellationToken cancellationToken = default) =>
        ExecuteAsync<VaultCertificate>("certificate.restore", null, Rules.Backup(backup), isWrite: true, async ct =>
        {
            KeyVaultCertificateWithPolicy certificate = await Client.RestoreCertificateBackupAsync(backup, ct).ConfigureAwait(false);
            return ToModel(certificate);
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result> CheckAccessAsync(CancellationToken cancellationToken = default) =>
        ExecuteAsync("certificate.health", null, null, isWrite: false, async ct =>
        {
            // Apenas metadados, uma página de um item: confirma rede, autenticação e permissão de listar certificados
            await foreach (var _ in Client.GetPropertiesOfCertificatesAsync(includePending: false, ct).AsPages(pageSizeHint: 1).ConfigureAwait(false))
                break;
        }, cancellationToken);

    private async Task<KeyVaultCertificate> GetAzureCertificateAsync(string name, string? version, CancellationToken cancellationToken) =>
        version is null
            ? (await Client.GetCertificateAsync(name, cancellationToken).ConfigureAwait(false)).Value
            : (await Client.GetCertificateVersionAsync(name, version, cancellationToken).ConfigureAwait(false)).Value;

    /// <summary>Regras gerais (<see cref="VaultCertificateRules.Create"/>) mais o formato de nome de emissor do Key Vault.</summary>
    internal static Error? ValidateCreate(CreateCertificateOptions options)
    {
        if (VaultCertificateRules.Create(options) is { } error)
            return error;
        return options.Issuer is null || IssuerPattern().IsMatch(options.Issuer) ? null : VaultErrors.InvalidInput("issuer", "Emissor inválido.");
    }
    internal static CertificatePolicy BuildPolicy(CreateCertificateOptions options)
    {
        string issuer = options.Issuer ?? SelfIssuer;
        var policy = options.DnsNames is { Count: > 0 } dnsNames
            ? new CertificatePolicy(issuer, options.Subject, BuildSans(dnsNames))
            : new CertificatePolicy(issuer, options.Subject);

        policy.ValidityInMonths = options.ValidityInMonths;
        policy.Exportable = options.Exportable;
        policy.ReuseKey = false;
        policy.ContentType = options.ContentFormat == CertificateContentFormat.Pem ? CertificateContentType.Pem : CertificateContentType.Pkcs12;

        if (options.KeyType == VaultKeyType.Rsa)
        {
            policy.KeyType = options.HardwareProtected ? CertificateKeyType.RsaHsm : CertificateKeyType.Rsa;
            policy.KeySize = options.KeySize;
        }
        else
        {
            policy.KeyType = options.HardwareProtected ? CertificateKeyType.EcHsm : CertificateKeyType.Ec;
            policy.KeyCurveName = options.Curve switch
            {
                VaultKeyCurve.P256 => CertificateKeyCurveName.P256,
                VaultKeyCurve.P384 => CertificateKeyCurveName.P384,
                _ => CertificateKeyCurveName.P521
            };
        }

        if (options.AutoRenewDaysBeforeExpiry is { } days)
            policy.LifetimeActions.Add(new LifetimeAction(CertificatePolicyAction.AutoRenew) { DaysBeforeExpiry = days });

        return policy;
    }

    private static SubjectAlternativeNames BuildSans(IEnumerable<string> dnsNames)
    {
        var sans = new SubjectAlternativeNames();
        foreach (var dns in dnsNames)
            sans.DnsNames.Add(dns);
        return sans;
    }

    internal static CertificateProperties ToModel(AzCertificateProperties properties) => new()
    {
        Name = properties.Name,
        Version = properties.Version,
        Id = properties.Id?.ToString(),
        Enabled = properties.Enabled ?? false,
        CreatedOn = properties.CreatedOn,
        UpdatedOn = properties.UpdatedOn,
        ExpiresOn = properties.ExpiresOn,
        NotBefore = properties.NotBefore,
        Thumbprint = properties.X509Thumbprint is null ? null : Convert.ToHexString(properties.X509Thumbprint),
        Tags = CopyTags(properties.Tags)
    };

    internal static VaultCertificate ToModel(KeyVaultCertificate certificate) => new()
    {
        Properties = ToModel(certificate.Properties),
        Cer = certificate.Cer
    };


    // \z e não $: $ aceitaria uma quebra de linha no final
    [GeneratedRegex(@"^[0-9a-zA-Z-]{1,127}\z", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 100)]
    private static partial Regex IssuerPattern();
}
