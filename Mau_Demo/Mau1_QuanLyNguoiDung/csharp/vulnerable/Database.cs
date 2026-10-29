using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace UserManager;

public static class Database
{
    private static readonly (string User, string Pass, string Name, string Email, string Role)[] SeedUsers =
    {
        ("admin", "admin123", "Quản trị viên", "admin@demo.local", "admin"),
        ("nguyenvana", "matkhau1", "Nguyễn Văn A", "vana@demo.local", "user"),
        ("tranthib", "123456", "Trần Thị B", "thib@demo.local", "user"),
        ("levanc", "levanc@2024", "Lê Văn C", "vanc@demo.local", "user"),
    };

    // [LỖ HỔNG 3 - Weak Cryptography] MD5 nhanh, không salt -> dễ bị bẻ bằng bảng cầu vồng.
    public static string HashPassword(string password)
    {
        using var md5 = MD5.Create();
        return Convert.ToHexString(md5.ComputeHash(Encoding.UTF8.GetBytes(password))).ToLowerInvariant();
    }

    public static void Initialize()
    {
        using var conn = new SqliteConnection("Data Source=users.db");
        conn.Open();
        using (var create = conn.CreateCommand())
        {
            create.CommandText = "DROP TABLE IF EXISTS users; CREATE TABLE users (id INTEGER PRIMARY KEY, " +
                                 "username TEXT UNIQUE, password_hash TEXT, full_name TEXT, email TEXT, role TEXT)";
            create.ExecuteNonQuery();
        }
        foreach (var u in SeedUsers)
        {
            using var insert = conn.CreateCommand();
            insert.CommandText = "INSERT INTO users (username, password_hash, full_name, email, role) " +
                                 "VALUES (@u, @h, @n, @e, @r)";
            insert.Parameters.AddWithValue("@u", u.User);
            insert.Parameters.AddWithValue("@h", HashPassword(u.Pass));
            insert.Parameters.AddWithValue("@n", u.Name);
            insert.Parameters.AddWithValue("@e", u.Email);
            insert.Parameters.AddWithValue("@r", u.Role);
            insert.ExecuteNonQuery();
        }
    }
}
