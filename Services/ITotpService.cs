namespace IISWeb.Services;

public interface ITotpService
{
    /// <summary>Generates a 20-byte cryptographic random secret, Base32-encoded.</summary>
    string GenerateSecret();

    /// <summary>Validates a 6-digit TOTP code against the secret with a ±1 step tolerance.</summary>
    bool Validate(string base32Secret, string code);

    /// <summary>otpauth:// URI suitable for QR codes (RFC 6238 / Google Authenticator).</summary>
    string BuildOtpAuthUri(string issuer, string accountName, string base32Secret);

    /// <summary>SVG payload (utf8) of the QR code for an otpauth:// URI.</summary>
    string BuildQrCodeSvg(string otpAuthUri);

    /// <summary>Generates n one-time recovery codes and their SHA-256 hashes (hex).</summary>
    (IReadOnlyList<string> ClearCodes, IReadOnlyList<string> Hashes) GenerateRecoveryCodes(int count = 10);

    /// <summary>SHA-256 (hex) of a recovery code, normalised (uppercase, no dashes/spaces).</summary>
    string HashRecoveryCode(string code);
}
