using System.Globalization;
using System.Text.Json;
using TEC.Vault.Providers;
using TEC.Vault.Providers.Http;

namespace TEC.Vault.HashiCorpVault.Internal;

/// <summary>Versão de um item no KV v2 (metadados, sem valor).</summary>
internal sealed record KvVersionInfo(int Version, DateTimeOffset? CreatedOn, DateTimeOffset? DeletedOn, bool Destroyed)
{
    public bool Alive => DeletedOn is null && !Destroyed;
}

/// <summary>Metadados de um item no KV v2.</summary>
internal sealed record KvMetadata(string Name, int CurrentVersion, IReadOnlyList<KvVersionInfo> Versions, Dictionary<string, string> Custom,
    DateTimeOffset? CreatedOn, DateTimeOffset? UpdatedOn)
{
    public KvVersionInfo? Current => Versions.FirstOrDefault(v => v.Version == CurrentVersion);

    /// <summary>Item ativo: a versão atual não foi excluída nem destruída.</summary>
    public bool Exists => Current is { Alive: true };

    /// <summary>Na lixeira: nenhuma versão ativa e ao menos uma excluída (recuperável).</summary>
    public bool IsDeleted => !Versions.Any(v => v.Alive) && Versions.Any(v => v.DeletedOn is not null && !v.Destroyed);
}

/// <summary>Uma pasta do KV v2 (<c>{mount}/data/{pasta}/{nome}</c>), usada pelos segredos e pelos certificados.</summary>
internal sealed class KvFolder(HashiCorpVaultClient client, string? folder)
{
    private string Mount => VaultEndpoint.Path(client.Options.Kv.Mount);

    private string? Folder => folder is null ? null : VaultEndpoint.Path(folder);

    /// <summary>Identificador informativo do item (<c>mount/pasta/nome</c>).</summary>
    internal string Id(string name) => string.Join('/', new[] { client.Options.Kv.Mount, folder, name }.Where(p => !string.IsNullOrEmpty(p)));

    internal async Task<KvMetadata?> MetadataAsync(string name, CancellationToken ct)
    {
        using var response = await client.GetAsync(HashiCorpVaultClient.Path(Mount, "metadata", Folder, VaultEndpoint.Segment(name)), ct).ConfigureAwait(false);
        if (response is null)
            return null;

        var data = response.Data;
        var versions = new List<KvVersionInfo>();
        if (data.TryGetProperty("versions", out var map) && map.ValueKind == JsonValueKind.Object)
        {
            foreach (var version in map.EnumerateObject())
            {
                if (!int.TryParse(version.Name, NumberStyles.None, CultureInfo.InvariantCulture, out var number))
                    continue;
                versions.Add(new KvVersionInfo(number, VaultJson.Date(version.Value, "created_time"), VaultJson.Date(version.Value, "deletion_time"),
                    version.Value.TryGetProperty("destroyed", out var destroyed) && destroyed.ValueKind == JsonValueKind.True));
            }
        }

        versions.Sort((a, b) => a.Version.CompareTo(b.Version));
        var current = data.TryGetProperty("current_version", out var c) && c.TryGetInt32(out var cv) ? cv : versions.LastOrDefault()?.Version ?? 0;
        return new KvMetadata(name, current, versions, VaultJson.Map(data, "custom_metadata"),
            VaultJson.Date(data, "created_time"), VaultJson.Date(data, "updated_time"));
    }

    /// <summary>Campos de uma versão (atual ou a informada). Versão excluída, destruída ou inexistente → <c>null</c>.</summary>
    internal async Task<(Dictionary<string, string> Fields, int Version, DateTimeOffset? CreatedOn)?> ReadAsync(string name, int? version, CancellationToken ct)
    {
        var path = HashiCorpVaultClient.Path(Mount, "data", Folder, VaultEndpoint.Segment(name));
        if (version is { } v)
            path += "?version=" + v.ToString(CultureInfo.InvariantCulture);

        using var response = await client.GetAsync(path, ct).ConfigureAwait(false);
        if (response is null)
            return null;

        var data = response.Data;
        if (!data.TryGetProperty("data", out var fields) || fields.ValueKind != JsonValueKind.Object ||
            !data.TryGetProperty("metadata", out var metadata) || metadata.ValueKind != JsonValueKind.Object)
            return null;   // versão excluída ou destruída: o Vault devolve data = null

        var number = metadata.TryGetProperty("version", out var n) && n.TryGetInt32(out var nv) ? nv : 0;
        return (VaultJson.Map(data, "data"), number, VaultJson.Date(metadata, "created_time"));
    }

    /// <summary>Grava uma nova versão com os campos informados. Retorna o número da versão.</summary>
    internal async Task<(int Version, DateTimeOffset? CreatedOn)> WriteAsync(string name, IReadOnlyDictionary<string, string> fields, CancellationToken ct)
    {
        var body = HashiCorpVaultClient.Json(w =>
        {
            w.WriteStartObject("data");
            foreach (var (key, value) in fields)
                w.WriteString(key, value);
            w.WriteEndObject();
        });

        // Gravação não é idempotente (cria versão): só é repetida após 429
        using var response = await client.SendAsync(HttpMethod.Post, HashiCorpVaultClient.Path(Mount, "data", Folder, VaultEndpoint.Segment(name)), body,
            idempotent: false, ct).ConfigureAwait(false);
        var data = response?.Data ?? throw new JsonException("Resposta sem data.");
        var version = data.TryGetProperty("version", out var v) && v.TryGetInt32(out var number) ? number : 0;
        return (version, VaultJson.Date(data, "created_time"));
    }

    /// <summary>Substitui os metadados livres (tags).</summary>
    internal async Task SetCustomMetadataAsync(string name, IReadOnlyDictionary<string, string> custom, CancellationToken ct)
    {
        var body = HashiCorpVaultClient.Json(w =>
        {
            w.WriteStartObject("custom_metadata");
            foreach (var (key, value) in custom)
                w.WriteString(key, value);
            w.WriteEndObject();
        });
        using var _ = await client.SendAsync(HttpMethod.Post, HashiCorpVaultClient.Path(Mount, "metadata", Folder, VaultEndpoint.Segment(name)), body,
            idempotent: true, ct).ConfigureAwait(false);
    }

    internal Task<List<string>> ListAsync(CancellationToken ct) =>
        client.ListAsync(HashiCorpVaultClient.Path(Mount, "metadata", Folder), ct);

    /// <summary>Exclusão lógica (recuperável) das versões informadas.</summary>
    internal Task DeleteVersionsAsync(string name, IEnumerable<int> versions, CancellationToken ct) =>
        VersionsAsync("delete", name, versions, ct);

    /// <summary>Recupera versões excluídas.</summary>
    internal Task UndeleteAsync(string name, IEnumerable<int> versions, CancellationToken ct) =>
        VersionsAsync("undelete", name, versions, ct);

    /// <summary>Remove o item e todas as versões, definitivamente.</summary>
    internal async Task DestroyAsync(string name, CancellationToken ct)
    {
        using var _ = await client.SendAsync(HttpMethod.Delete, HashiCorpVaultClient.Path(Mount, "metadata", Folder, VaultEndpoint.Segment(name)), null,
            idempotent: true, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Nome real do item: o informado ou, sem ele, o único igual sem diferenciar maiúsculas (o KV diferencia; o TEC.Vault não).
    /// Dois candidatos → <c>Ambiguous</c>.
    /// </summary>
    internal async Task<(KvMetadata? Metadata, bool Ambiguous)> ResolveAsync(string name, CancellationToken ct)
    {
        if (await MetadataAsync(name, ct).ConfigureAwait(false) is { } exact)
            return (exact, false);

        var names = await ListAsync(ct).ConfigureAwait(false);
        if (names.Count > client.Options.MaxListItems)
            throw new VaultListLimitExceededException(client.Options.MaxListItems);   // vira VaultErrors.TooManyItems
        var matches = names
            .Where(n => !string.Equals(n, name, StringComparison.Ordinal) && string.Equals(n, name, StringComparison.OrdinalIgnoreCase))
            .ToList();
        return matches.Count switch
        {
            0 => (null, false),
            1 => (await MetadataAsync(matches[0], ct).ConfigureAwait(false), false),
            _ => (null, true)
        };
    }

    private async Task VersionsAsync(string operation, string name, IEnumerable<int> versions, CancellationToken ct)
    {
        var list = versions.ToList();
        if (list.Count == 0)
            return;
        var body = HashiCorpVaultClient.Json(w =>
        {
            w.WriteStartArray("versions");
            foreach (var v in list)
                w.WriteNumberValue(v);
            w.WriteEndArray();
        });
        using var _ = await client.SendAsync(HttpMethod.Post, HashiCorpVaultClient.Path(Mount, operation, Folder, VaultEndpoint.Segment(name)), body,
            idempotent: true, ct).ConfigureAwait(false);
    }
}
