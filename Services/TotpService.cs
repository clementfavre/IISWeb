using System.Security.Cryptography;
using System.Text;
using QRCoder;

namespace IISWeb.Services;

/// <summary>
/// RFC 6238 TOTP-SHA1, 30 s period, 6 digits — the parameters every authenticator
/// app supports without explicit configuration.
/// </summary>
public class TotpService : ITotpService
{
    private const int StepSeconds = 30;
    private const int Digits = 6;
    private const int WindowSteps = 1; // accept ±1 step (=30s) drift

    private static readonly char[] Base32Alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".ToCharArray();

    public string GenerateSecret()
    {
        var bytes = RandomNumberGenerator.GetBytes(20);
        return Base32Encode(bytes);
    }

    public bool Validate(string base32Secret, string code)
    {
        if (string.IsNullOrWhiteSpace(base32Secret) || string.IsNullOrWhiteSpace(code))
            return false;

        var trimmed = new string(code.Where(char.IsDigit).ToArray());
        if (trimmed.Length != Digits)
            return false;

        byte[] key;
        try
        {
            key = Base32Decode(base32Secret);
        }
        catch (FormatException)
        {
            return false;
        }
        if (key.Length == 0)
            return false;

        var step = (long)(DateTimeOffset.UtcNow.ToUnixTimeSeconds() / StepSeconds);

        for (var w = -WindowSteps; w <= WindowSteps; w++)
        {
            var candidate = ComputeTotp(key, step + w);
            if (FixedTimeEquals(candidate, trimmed))
                return true;
        }
        return false;
    }

    public string BuildOtpAuthUri(string issuer, string accountName, string base32Secret)
    {
        var i = Uri.EscapeDataString(issuer);
        var a = Uri.EscapeDataString(accountName);
        // Authenticator apps expect the secret without padding.
        var secret = base32Secret.TrimEnd('=');
        return $"otpauth://totp/{i}:{a}?secret={secret}&issuer={i}&algorithm=SHA1&digits={Digits}&period={StepSeconds}";
    }

    public string BuildQrCodeSvg(string otpAuthUri)
    {
        using var generator = new QRCodeGenerator();
        using var data = generator.CreateQrCode(otpAuthUri, QRCodeGenerator.ECCLevel.Q);
        var svg = new SvgQRCode(data);
        return svg.GetGraphic(4);
    }

    public (IReadOnlyList<string> ClearCodes, IReadOnlyList<string> Hashes) GenerateRecoveryCodes(int count = 10)
    {
        const string alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // ambiguous chars removed
        var clear = new List<string>(count);
        var hashes = new List<string>(count);
        for (var n = 0; n < count; n++)
        {
            var sb = new StringBuilder(11);
            for (var i = 0; i < 10; i++)
            {
                if (i == 5) sb.Append('-');
                sb.Append(alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)]);
            }
            var code = sb.ToString();
            clear.Add(code);
            hashes.Add(HashRecoveryCode(code));
        }
        return (clear, hashes);
    }

    public string HashRecoveryCode(string code)
    {
        var normalised = new string((code ?? string.Empty)
            .Where(c => !char.IsWhiteSpace(c) && c != '-')
            .Select(char.ToUpperInvariant)
            .ToArray());
        var bytes = Encoding.UTF8.GetBytes(normalised);
        return Convert.ToHexString(SHA256.HashData(bytes));
    }

    private static string ComputeTotp(byte[] key, long step)
    {
        Span<byte> counter = stackalloc byte[8];
        for (var i = 7; i >= 0; i--)
        {
            counter[i] = (byte)(step & 0xff);
            step >>= 8;
        }

        Span<byte> hash = stackalloc byte[20];
        if (!HMACSHA1.TryHashData(key, counter, hash, out _))
            throw new InvalidOperationException("HMAC-SHA1 failed.");

        var offset = hash[19] & 0x0f;
        var binary =
            ((hash[offset] & 0x7f) << 24) |
            ((hash[offset + 1] & 0xff) << 16) |
            ((hash[offset + 2] & 0xff) << 8) |
            (hash[offset + 3] & 0xff);

        var modulus = (int)Math.Pow(10, Digits);
        var otp = binary % modulus;
        return otp.ToString().PadLeft(Digits, '0');
    }

    private static bool FixedTimeEquals(string a, string b)
    {
        if (a.Length != b.Length) return false;
        var diff = 0;
        for (var i = 0; i < a.Length; i++)
            diff |= a[i] ^ b[i];
        return diff == 0;
    }

    private static string Base32Encode(byte[] data)
    {
        var sb = new StringBuilder((data.Length + 4) / 5 * 8);
        for (var i = 0; i < data.Length; i += 5)
        {
            var chunk = new byte[5];
            var len = Math.Min(5, data.Length - i);
            Array.Copy(data, i, chunk, 0, len);

            ulong buffer = 0;
            for (var j = 0; j < 5; j++)
                buffer = (buffer << 8) | chunk[j];

            int bitsToOutput = len switch { 1 => 2, 2 => 4, 3 => 5, 4 => 7, _ => 8 };
            for (var j = 0; j < 8; j++)
            {
                if (j < bitsToOutput)
                {
                    var index = (int)((buffer >> (35 - j * 5)) & 0x1F);
                    sb.Append(Base32Alphabet[index]);
                }
                else
                {
                    sb.Append('=');
                }
            }
        }
        return sb.ToString();
    }

    private static byte[] Base32Decode(string s)
    {
        s = s.Trim().TrimEnd('=').ToUpperInvariant();
        if (s.Length == 0) return Array.Empty<byte>();

        var output = new List<byte>(s.Length * 5 / 8);
        var buffer = 0;
        var bitsLeft = 0;

        foreach (var c in s)
        {
            var idx = Array.IndexOf(Base32Alphabet, c);
            if (idx < 0) throw new FormatException($"Invalid Base32 character '{c}'.");
            buffer = (buffer << 5) | idx;
            bitsLeft += 5;
            if (bitsLeft >= 8)
            {
                bitsLeft -= 8;
                output.Add((byte)((buffer >> bitsLeft) & 0xff));
            }
        }
        return output.ToArray();
    }
}
