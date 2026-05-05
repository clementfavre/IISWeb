using System.ComponentModel.DataAnnotations;

namespace IISWeb.Models;

public class AuditLog
{
    public int Id { get; set; }
    public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;

    [MaxLength(64)] public string? UserName { get; set; }
    [MaxLength(64)] public string? IpAddress { get; set; }

    [Required, MaxLength(64)]
    public string Action { get; set; } = string.Empty;

    [MaxLength(128)] public string? AppPool { get; set; }

    [Required] public bool Success { get; set; }

    [MaxLength(512)] public string? Message { get; set; }

    /// <summary>Hex-encoded SHA-256 of the previous row's RowHash. Empty for the genesis row.</summary>
    [MaxLength(64)]
    public string PrevHash { get; set; } = string.Empty;

    /// <summary>Hex-encoded SHA-256 over PrevHash || canonical fields. Detects tampering.</summary>
    [MaxLength(64)]
    public string RowHash { get; set; } = string.Empty;
}

public static class AuditActions
{
    public const string Login = "Login";
    public const string LoginMfa = "LoginMfa";
    public const string Logout = "Logout";
    public const string Start = "Start";
    public const string Stop = "Stop";
    public const string Recycle = "Recycle";

    public const string PasswordChange = "PasswordChange";
    public const string MfaEnable = "MfaEnable";
    public const string MfaDisable = "MfaDisable";
    public const string MfaRecoveryUsed = "MfaRecoveryUsed";

    public const string UserCreate = "UserCreate";
    public const string UserUpdate = "UserUpdate";
    public const string UserDelete = "UserDelete";
    public const string UserResetPwd = "UserResetPwd";
    public const string UserUnlock = "UserUnlock";
    public const string UserDisableMfa = "UserDisableMfa";
}
