using System.Text;
using Microsoft.Extensions.Hosting;

namespace TEC.Vault.Providers.Http;

/// <summary>Validação do endereço de um cofre acessado por HTTP (uso pelos provedores).</summary>
public static class VaultEndpoint
{
    /// <summary>
    /// Confere o endereço do cofre: absoluto, HTTPS, sem usuário, query, fragmento ou caminho. HTTP só para
    /// <c>localhost</c>/loopback em Development (cofre local de desenvolvimento, ex.: <c>vault server -dev</c>).
    /// </summary>
    /// <remarks>
    /// Um endereço adulterado na configuração enviaria o token de acesso (ou a credencial de login) para outro servidor: por isso
    /// o esquema e a forma são verificados na inicialização, e o cliente HTTP não segue redirecionamentos.
    /// </remarks>
    /// <param name="address">Endereço configurado.</param>
    /// <param name="optionName">Nome da opção (para a mensagem).</param>
    /// <param name="environment">Ambiente da aplicação (para liberar HTTP local em Development).</param>
    /// <returns>Endereço normalizado, terminado em <c>/</c>.</returns>
    /// <exception cref="InvalidOperationException">Endereço inválido.</exception>
    public static Uri Validate(Uri? address, string optionName, IHostEnvironment? environment = null)
    {
        if (address is null)
            throw new InvalidOperationException($"{optionName} é obrigatório.");
        if (!address.IsAbsoluteUri)
            throw new InvalidOperationException($"{optionName} deve ser um endereço absoluto.");

        var localHttp = address.Scheme == Uri.UriSchemeHttp && address.IsLoopback && VaultEnvironment.IsDevelopment(environment);
        if (address.Scheme != Uri.UriSchemeHttps && !localHttp)
            throw new InvalidOperationException($"{optionName} deve usar HTTPS (HTTP só em localhost no ambiente Development).");
        if (!string.IsNullOrEmpty(address.UserInfo) || !string.IsNullOrEmpty(address.Query) || !string.IsNullOrEmpty(address.Fragment))
            throw new InvalidOperationException($"{optionName} não pode ter usuário, query ou fragmento.");
        if (address.AbsolutePath != "/")
            throw new InvalidOperationException($"{optionName} deve ser só o endereço do servidor, sem caminho.");

        return new Uri(address.GetLeftPart(UriPartial.Authority) + "/");
    }

    /// <summary>
    /// Codifica um segmento de caminho (nome de item, mount) para a URL, sem permitir que ele altere a estrutura do caminho.
    /// </summary>
    /// <exception cref="ArgumentException">Segmento vazio, <c>.</c> ou <c>..</c>.</exception>
    public static string Segment(string value)
    {
        ArgumentException.ThrowIfNullOrEmpty(value);
        if (value is "." or "..")
            throw new ArgumentException("Segmento de caminho inválido.", nameof(value));
        return Uri.EscapeDataString(value);
    }

    /// <summary>
    /// Codifica um caminho com vários segmentos separados por <c>/</c> (ex.: <c>minha-api/db</c>), recusando segmentos vazios,
    /// <c>.</c> e <c>..</c>.
    /// </summary>
    public static string Path(string value)
    {
        ArgumentException.ThrowIfNullOrEmpty(value);
        var builder = new StringBuilder(value.Length + 8);
        foreach (var part in value.Split('/'))
        {
            if (builder.Length > 0)
                builder.Append('/');
            builder.Append(Segment(part));
        }

        return builder.ToString();
    }
}
