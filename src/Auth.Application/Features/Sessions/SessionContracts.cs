namespace Auth.Application.Features.Sessions;

public sealed record SessionDto(
    Guid Id,
    string Kind,
    string LoginMethod,
    string? IpAddress,
    string? UserAgent,
    DateTime CreatedAt,
    DateTime LastSeenAt,
    DateTime ExpiresAt,
    bool Current);

public sealed record RevokeSessionResponse(bool WasCurrent);
