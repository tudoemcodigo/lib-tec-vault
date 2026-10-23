// ARQUIVO CANÔNICO: mantido em tudoemcodigo/tec-workflows (template/build/Polyfills). Não edite no componente.
//
// System.Threading.Lock (nativo no .NET 9+) para o alvo net8.0. O build/Tec.Build.props compila este arquivo só nos
// pacotes e só no net8.0, como tipo INTERNAL de cada assembly (não vaza para quem consome o pacote).
// Assim o código usa sempre `private readonly Lock _sync = new();` e `lock (_sync) { ... }`, sem #if: no .NET 9+ o
// compilador usa o Lock nativo (EnterScope, mais rápido que Monitor); no net8.0, este equivalente sobre Monitor.
#if !NET9_0_OR_GREATER
namespace System.Threading;

/// <summary>Equivalente a <c>System.Threading.Lock</c> para .NET 8, implementado com <see cref="Monitor"/>.</summary>
internal sealed class Lock
{
    // Objeto separado: o compilador recusa (CS9216) usar o próprio Lock como objeto de Monitor
    private readonly object _monitor = new();

    /// <summary>Indica se a thread atual detém a trava.</summary>
    public bool IsHeldByCurrentThread => Monitor.IsEntered(_monitor);

    /// <summary>Entra na trava, esperando se necessário.</summary>
    public void Enter() => Monitor.Enter(_monitor);

    /// <summary>Tenta entrar na trava sem esperar.</summary>
    /// <returns><c>true</c> se a trava foi obtida.</returns>
    public bool TryEnter() => Monitor.TryEnter(_monitor);

    /// <summary>Sai da trava.</summary>
    public void Exit() => Monitor.Exit(_monitor);

    /// <summary>Entra na trava e devolve o escopo que sai dela no <c>Dispose</c> (usado pelo comando <c>lock</c>).</summary>
    /// <returns>Escopo da trava.</returns>
    public Scope EnterScope()
    {
        Monitor.Enter(_monitor);
        return new Scope(this);
    }

    /// <summary>Escopo de uma trava obtida por <see cref="EnterScope"/>.</summary>
    public ref struct Scope
    {
        private readonly Lock _owner;

        internal Scope(Lock owner) => _owner = owner;

        /// <summary>Sai da trava.</summary>
        public readonly void Dispose() => _owner.Exit();
    }
}
#endif
