using System.Security.Cryptography;
using Microsoft.Data.Sqlite;

namespace UserManager;

public static class Database
{
    private const int Iterations = 600_000;

    private static readonly (string User, string Name, string Email, string Role)[] SeedUsers =
    {
        ("admin", "Quản trị viên", "admin@demo.local", "admin"),
        ("nguyenvana", "Nguyễn Văn A", "vana@demo.local", "user"),
        ("tranthib", "Trần Thị B", "thib@demo.local", "user"),
        ("levanc", "Lê Văn C", "vanc@demo.local", "user"),
    };

    // [ĐÃ SỬA 3] PBKDF2-SHA256 chậm có chủ đích + salt ngẫu nhiên cho từng người dùng.
    public static string HashPassword(string password, byte[] salt)
    {
        return Convert.ToHexString(Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, 32));
    }

    public static bool VerifyPassword(string password, string saltHex, string expectedHex)
    {
        var actual = Convert.FromHexString(HashPassword(password, Convert.FromHexString(saltHex)));
        return CryptographicOperations.FixedTimeEquals(actual, Convert.FromHexString(expectedHex));
    }

    /// <summary>Tạo bảng và dữ liệu mẫu; trả về mật khẩu demo (từ DEMO_PASSWORD hoặc sinh ngẫu nhiên).</summary>
    public static string Initialize()
    {
        var demoPassword = Environment.GetEnvironmentVariable("DEMO_PASSWORD") is { Length: > 0 } fromEnv
            ? fromEnv
            : Convert.ToBase64String(RandomNumberGenerator.GetBytes(9));

        using var conn = new SqliteConnection("Data Source=users.db");
        conn.Open();
        using (var create = conn.CreateCommand())
        {
            create.CommandText = "DROP TABLE IF EXISTS users; CREATE TABLE users (id INTEGER PRIMARY KEY, " +
                                 "username TEXT UNIQUE, password_hash TEXT, salt TEXT, full_name TEXT, email TEXT, role TEXT)";
            create.ExecuteNonQuery();
        }
        foreach (var u in SeedUsers)
        {
            var salt = RandomNumberGenerator.GetBytes(16);
            using var insert = conn.CreateCommand();
            insert.CommandText = "INSERT INTO users (username, password_hash, salt, full_name, email, role) " +
                                 "VALUES (@u, @h, @s, @n, @e, @r)";
            insert.Parameters.AddWithValue("@u", u.User);
            insert.Parameters.AddWithValue("@h", HashPassword(demoPassword, salt));
            insert.Parameters.AddWithValue("@s", Convert.ToHexString(salt));
            insert.Parameters.AddWithValue("@n", u.Name);
            insert.Parameters.AddWithValue("@e", u.Email);
            insert.Parameters.AddWithValue("@r", u.Role);
            insert.ExecuteNonQuery();
        }
        return demoPassword;
    }
}
