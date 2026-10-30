namespace Auth.Domain.Common;

/// <summary>Violación de una invariante del dominio (error de programación, no de usuario).</summary>
public sealed class DomainException : Exception
{
    public DomainException()
    {
    }

    public DomainException(string message) : base(message)
    {
    }

    public DomainException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
