using IISWeb.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace IISWeb.Data;

public static class DbInitializer
{
    public const string EnvUser = "IISWEB_INITIAL_ADMIN_USER";
    public const string EnvPass = "IISWEB_INITIAL_ADMIN_PASS";

    public static async Task InitializeAsync(IServiceProvider sp, ILogger logger)
    {
        var db = sp.GetRequiredService<AppDbContext>();
        await db.Database.EnsureCreatedAsync();
        await EnsureSchemaAsync(db, logger);

        if (await db.Users.AnyAsync())
            return;

        var user = Environment.GetEnvironmentVariable(EnvUser);
        var pass = Environment.GetEnvironmentVariable(EnvPass);

        if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(pass))
        {
            logger.LogWarning(
                "No users in DB. To create the initial admin, either set {EnvUser}/{EnvPass} environment variables and restart, OR run: IISWeb.exe seed-admin --username <name> --password <pwd>",
                EnvUser, EnvPass);
            return;
        }

        try
        {
            var users = sp.GetRequiredService<IUserService>();
            await users.CreateAdminAsync(user, pass);
            logger.LogInformation("Initial admin '{User}' was created from environment variables.", user);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to seed initial admin from environment variables.");
        }
    }

    /// <summary>
    /// SQLite has no IF NOT EXISTS for ADD COLUMN. We probe each table with PRAGMA
    /// and add missing columns so existing databases survive an upgrade without
    /// EF migrations.
    /// </summary>
    private static async Task EnsureSchemaAsync(AppDbContext db, ILogger logger)
    {
        var conn = (SqliteConnection)db.Database.GetDbConnection();
        if (conn.State != System.Data.ConnectionState.Open)
            await conn.OpenAsync();

        await EnsureColumnAsync(conn, "Users", "MustChangePassword", "INTEGER NOT NULL DEFAULT 0", logger);
        await EnsureColumnAsync(conn, "Users", "TotpSecret", "TEXT NULL", logger);
        await EnsureColumnAsync(conn, "Users", "TotpEnabled", "INTEGER NOT NULL DEFAULT 0", logger);
        await EnsureColumnAsync(conn, "Users", "TotpRecoveryCodesJson", "TEXT NULL", logger);

        await EnsureColumnAsync(conn, "AuditLogs", "PrevHash", "TEXT NOT NULL DEFAULT ''", logger);
        await EnsureColumnAsync(conn, "AuditLogs", "RowHash", "TEXT NOT NULL DEFAULT ''", logger);
    }

    private static async Task<bool> ColumnExistsAsync(SqliteConnection conn, string table, string column)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"PRAGMA table_info({table});";
        using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            var name = reader.GetString(1);
            if (string.Equals(name, column, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static async Task EnsureColumnAsync(SqliteConnection conn, string table, string column, string sqlType, ILogger logger)
    {
        if (await ColumnExistsAsync(conn, table, column))
            return;

        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"ALTER TABLE {table} ADD COLUMN {column} {sqlType};";
        await cmd.ExecuteNonQueryAsync();
        logger.LogInformation("Schema upgraded: added column {Table}.{Column}", table, column);
    }
}
