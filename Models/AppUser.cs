using System.ComponentModel.DataAnnotations;

namespace IISWeb.Models;

public class AppUser
{
    public int Id { get; set; }

    [Required, MaxLength(64)]
    public string UserName { get; set; } = string.Empty;

    [Required]
    public string PasswordHash { get; set; } = string.Empty;

    [Required, MaxLength(32)]
    public string Role { get; set; } = Roles.Admin;

    public int FailedLoginAttempts { get; set; }
    public DateTime? LockoutUntilUtc { get; set; }
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    public DateTime? LastLoginUtc { get; set; }

    /// <summary>True when the user must change their password on next sign-in.</summary>
    public bool MustChangePassword { get; set; }

    /// <summary>Base32-encoded TOTP shared secret. Null when MFA is not enrolled.</summary>
    [MaxLength(64)]
    public string? TotpSecret { get; set; }

    /// <summary>True once the user has successfully verified their first TOTP code.</summary>
    public bool TotpEnabled { get; set; }

    /// <summary>JSON array of SHA-256 hashes (hex) of the unused recovery codes.</summary>
    public string? TotpRecoveryCodesJson { get; set; }
}

public static class Roles
{
    public const string Admin = "Admin";
    public const string Viewer = "Viewer";

    public static IReadOnlyList<string> All { get; } = new[] { Admin, Viewer };

    public static bool IsKnown(string? role) =>
        role is not null && (role == Admin || role == Viewer);
}
