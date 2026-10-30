namespace Auth.Application.Features.Account;

public sealed record MeResponse(
    Guid Id,
    string Email,
    bool EmailConfirmed,
    bool MfaEnabled,
    IReadOnlyList<string> Roles,
    IReadOnlyList<string> Permissions,
    DateTime CreatedAt);

public sealed record ChangePasswordRequest(string CurrentPassword, string NewPassword);

public sealed record MfaCodeRequest(string Code);

public sealed record DisableMfaRequest(string Password, string Code);

public sealed record MfaStatusResponse(bool Enabled, int RecoveryCodesLeft);

public sealed record MfaSetupResponse(string SharedKey, string OtpAuthUri);

public sealed record RecoveryCodesResponse(IReadOnlyList<string> Codes);
