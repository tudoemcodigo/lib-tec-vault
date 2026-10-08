using Microsoft.Extensions.Hosting;
using TEC.Vault.DependencyInjection;
using TEC.Vault.Providers.Http;

namespace TEC.Vault.HashiCorpVault;

/// <summary>Método de login no HashiCorp Vault. Nenhum exige segredo em texto na configuração.</summary>
public enum HashiCorpVaultAuthMethod
{
    /// <summary>
    /// Kubernetes: o token da service account do pod (<see cref="HashiCorpVaultAuthOptions.ServiceAccountTokenFile"/>) é trocado
    /// por um token do Vault, com o papel <see cref="HashiCorpVaultAuthOptions.Role"/>. Recomendado no Kubernetes.
    /// </summary>
    Kubernetes = 0,

    /// <summary>
    /// JWT/OIDC federado (GitHub Actions, workload identity de nuvem): o JWT lido de arquivo ou variável é trocado por um token
    /// do Vault, com o papel <see cref="HashiCorpVaultAuthOptions.Role"/>.
    /// </summary>
    Jwt = 1,

    /// <summary>
    /// AppRole: <see cref="HashiCorpVaultAuthOptions.RoleId"/> (não é segredo) e o secret_id lido de arquivo ou variável.
    /// </summary>
    AppRole = 2,

    /// <summary>
    /// Token pronto, lido de arquivo (ex.: o sink do Vault Agent, renovado por ele) ou variável. Relido a cada 401/403.
    /// </summary>
    Token = 3
}

/// <summary>Login no HashiCorp Vault.</summary>
public sealed class HashiCorpVaultAuthOptions
{
    /// <summary>Caminho padrão do token da service account no pod.</summary>
    public const string DefaultServiceAccountTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token";

    /// <summary>Método. Padrão: <see cref="HashiCorpVaultAuthMethod.Kubernetes"/>.</summary>
    public HashiCorpVaultAuthMethod Method { get; set; } = HashiCorpVaultAuthMethod.Kubernetes;

    /// <summary>Caminho do método de autenticação no Vault. Padrão: <c>kubernetes</c>, <c>jwt</c> ou <c>approle</c>, conforme o método.</summary>
    public string? Mount { get; set; }

    /// <summary>Papel (Kubernetes e JWT).</summary>
    public string? Role { get; set; }

    /// <summary>role_id (AppRole). Identifica o papel; não é segredo.</summary>
    public string? RoleId { get; set; }

    /// <summary>Token da service account (Kubernetes). Padrão: <see cref="DefaultServiceAccountTokenFile"/>.</summary>
    public string? ServiceAccountTokenFile { get; set; }

    /// <summary>Arquivo com o JWT (Jwt).</summary>
    public string? JwtFile { get; set; }

    /// <summary>Variável de ambiente com o JWT (Jwt).</summary>
    public string? JwtVariable { get; set; }

    /// <summary>Arquivo com o secret_id (AppRole).</summary>
    public string? SecretIdFile { get; set; }

    /// <summary>Variável de ambiente com o secret_id (AppRole).</summary>
    public string? SecretIdVariable { get; set; }

    /// <summary>Arquivo com o token (Token). Ex.: sink do Vault Agent.</summary>
    public string? TokenFile { get; set; }

    /// <summary>Variável de ambiente com o token (Token). Ex.: <c>VAULT_TOKEN</c>.</summary>
    public string? TokenVariable { get; set; }

    internal string EffectiveMount => Mount ?? Method switch
    {
        HashiCorpVaultAuthMethod.Kubernetes => "kubernetes",
        HashiCorpVaultAuthMethod.Jwt => "jwt",
        HashiCorpVaultAuthMethod.AppRole => "approle",
        _ => "token"
    };

    internal VaultCredentialInput Credential() => Method switch
    {
        HashiCorpVaultAuthMethod.Kubernetes => VaultCredentialInput.Create(ServiceAccountTokenFile, null,
            "HashiCorpVaultOptions.Auth.ServiceAccountTokenFile", "-", DefaultServiceAccountTokenFile),
        HashiCorpVaultAuthMethod.Jwt => VaultCredentialInput.Create(JwtFile, JwtVariable,
            "HashiCorpVaultOptions.Auth.JwtFile", "HashiCorpVaultOptions.Auth.JwtVariable"),
        HashiCorpVaultAuthMethod.AppRole => VaultCredentialInput.Create(SecretIdFile, SecretIdVariable,
            "HashiCorpVaultOptions.Auth.SecretIdFile", "HashiCorpVaultOptions.Auth.SecretIdVariable"),
        HashiCorpVaultAuthMethod.Token => VaultCredentialInput.Create(TokenFile, TokenVariable,
            "HashiCorpVaultOptions.Auth.TokenFile", "HashiCorpVaultOptions.Auth.TokenVariable"),
        _ => throw new InvalidOperationException("HashiCorpVaultOptions.Auth.Method inválido.")
    };

    internal void Validate()
    {
        if (!Enum.IsDefined(Method))
            throw new InvalidOperationException("HashiCorpVaultOptions.Auth.Method inválido.");
        if (Method is HashiCorpVaultAuthMethod.Kubernetes or HashiCorpVaultAuthMethod.Jwt && string.IsNullOrWhiteSpace(Role))
            throw new InvalidOperationException($"HashiCorpVaultOptions.Auth.Role é obrigatório no método {Method}.");
        if (Method == HashiCorpVaultAuthMethod.AppRole && string.IsNullOrWhiteSpace(RoleId))
            throw new InvalidOperationException("HashiCorpVaultOptions.Auth.RoleId é obrigatório no AppRole.");
        HashiCorpVaultOptions.ValidatePath(EffectiveMount, "HashiCorpVaultOptions.Auth.Mount");
        Credential();
    }
}

/// <summary>Segredos (e certificados) no KV v2.</summary>
public sealed class HashiCorpVaultKvOptions
{
    /// <summary>Caminho do KV v2. Padrão: <c>secret</c>.</summary>
    public string Mount { get; set; } = "secret";

    /// <summary>Pasta da aplicação dentro do KV (ex.: <c>minha-api</c>). Vazio: a raiz do KV. Recomendado: uma pasta por aplicação.</summary>
    public string? BasePath { get; set; }

    /// <summary>Campo do KV que guarda o valor do segredo. Padrão: <c>value</c>.</summary>
    public string ValueField { get; set; } = "value";

    /// <summary>Pasta dos certificados, relativa a <see cref="BasePath"/>. Padrão: <c>_certificates</c> (nunca colide com nome de segredo).</summary>
    public string CertificatesPath { get; set; } = "_certificates";
}

/// <summary>Chaves no Transit.</summary>
public sealed class HashiCorpVaultTransitOptions
{
    /// <summary>Caminho do Transit. Padrão: <c>transit</c>.</summary>
    public string Mount { get; set; } = "transit";
}

/// <summary>Emissão de certificados pelo PKI.</summary>
public sealed class HashiCorpVaultPkiOptions
{
    /// <summary>Caminho do PKI. Padrão: <c>pki</c>.</summary>
    public string Mount { get; set; } = "pki";

    /// <summary>Papel usado na emissão (<c>{Mount}/sign/{Role}</c>). <c>null</c>: só certificados autoassinados (<c>Issuer = "Self"</c>) e importados.</summary>
    public string? Role { get; set; }
}

/// <summary>Configuração do provedor HashiCorp Vault (também compatível com OpenBao).</summary>
public sealed class HashiCorpVaultOptions
{
    /// <summary>Endereço do servidor (ex.: <c>https://vault.interno:8200</c>). Obrigatório. HTTPS (HTTP só em localhost em Development).</summary>
    public Uri? Address { get; set; }

    /// <summary>Namespace (Vault Enterprise e HCP Vault). <c>null</c>: nenhum.</summary>
    public string? Namespace { get; set; }

    /// <summary>Login.</summary>
    public HashiCorpVaultAuthOptions Auth { get; } = new();

    /// <summary>Segredos e certificados (KV v2).</summary>
    public HashiCorpVaultKvOptions Kv { get; } = new();

    /// <summary>Chaves (Transit).</summary>
    public HashiCorpVaultTransitOptions Transit { get; } = new();

    /// <summary>Emissão de certificados (PKI).</summary>
    public HashiCorpVaultPkiOptions Pki { get; } = new();

    /// <summary>Stores registrados por <c>UseHashiCorpVault</c>. Padrão: <see cref="VaultStores.All"/>. Ignorado no registro por configuração.</summary>
    public VaultStores Stores { get; set; } = VaultStores.All;

    /// <summary>
    /// Máximo de itens de uma listagem (segredos, certificados, chaves e itens excluídos), de 1 a 1.000.000. Padrão: 10.000.
    /// A listagem do KV/Transit lê os metadados de cada item (uma chamada por item): acima do limite ela falha com
    /// <c>VaultErrors.TooManyItems</c> logo após a listagem de nomes, sem ler nenhum item.
    /// </summary>
    public int MaxListItems { get; set; } = 10_000;

    /// <summary>Transporte HTTP (tentativas, tempo limite, handler com CA interna ou proxy).</summary>
    public VaultHttpSettings Http { get; } = new();

    /// <summary>Ambiente da aplicação (libera HTTP em localhost só em Development).</summary>
    public IHostEnvironment? HostEnvironment { get; set; }

    /// <summary>Relógio. Padrão: <see cref="System.TimeProvider.System"/>.</summary>
    public TimeProvider? TimeProvider { get; set; }

    internal Uri Validate()
    {
        var address = VaultEndpoint.Validate(Address, "HashiCorpVaultOptions.Address", HostEnvironment);
        if (Namespace is not null)
            ValidatePath(Namespace, "HashiCorpVaultOptions.Namespace");
        Auth.Validate();
        ValidatePath(Kv.Mount, "HashiCorpVaultOptions.Kv.Mount");
        if (!string.IsNullOrEmpty(Kv.BasePath))
            ValidatePath(Kv.BasePath, "HashiCorpVaultOptions.Kv.BasePath");
        ValidatePath(Kv.CertificatesPath, "HashiCorpVaultOptions.Kv.CertificatesPath");
        if (string.IsNullOrWhiteSpace(Kv.ValueField) || Kv.ValueField.Length > 128)
            throw new InvalidOperationException("HashiCorpVaultOptions.Kv.ValueField é obrigatório (até 128 caracteres).");
        ValidatePath(Transit.Mount, "HashiCorpVaultOptions.Transit.Mount");
        ValidatePath(Pki.Mount, "HashiCorpVaultOptions.Pki.Mount");
        if (Pki.Role is not null)
            ValidatePath(Pki.Role, "HashiCorpVaultOptions.Pki.Role");
        Http.Validate("HashiCorpVaultOptions.Http");
        if (MaxListItems is < 1 or > 1_000_000)
            throw new InvalidOperationException("HashiCorpVaultOptions.MaxListItems deve estar entre 1 e 1.000.000.");
        return address;
    }

    /// <summary>Caminho com segmentos de letras, números, hífen, sublinhado e ponto, sem <c>.</c>/<c>..</c> e sem barras nas pontas.</summary>
    internal static void ValidatePath(string? value, string option)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 512 || value.StartsWith('/') || value.EndsWith('/') ||
            value.Split('/').Any(p => p.Length == 0 || p is "." or ".." || !p.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.')))
            throw new InvalidOperationException($"{option} inválido: use segmentos com letras, números, hífen, sublinhado e ponto, separados por / (sem / nas pontas).");
    }
}
