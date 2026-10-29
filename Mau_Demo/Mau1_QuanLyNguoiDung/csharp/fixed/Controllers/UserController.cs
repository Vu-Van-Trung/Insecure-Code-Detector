// Mẫu 1 - Website quản lý người dùng (C# / ASP.NET Core) - BẢN ĐÃ SỬA.
//
// Đối chiếu với ../vulnerable/Controllers/UserController.cs:
//   [1] Hardcoded Secret  -> đọc khóa từ biến môi trường, không có thì sinh ngẫu nhiên
//   [2] SQL Injection     -> SqliteCommand với tham số @username, @pattern
//   [3] Weak Cryptography -> PBKDF2-SHA256 + salt (xem Database.cs), so sánh thời gian hằng
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;

namespace UserManager.Controllers;

[ApiController]
[Route("api")]
public class UserController : ControllerBase
{
    private const string ConnectionString = "Data Source=users.db";

    // [ĐÃ SỬA 1] Secret nằm ngoài mã nguồn (biến môi trường / User Secrets / Key Vault).
    private static readonly byte[] TokenSigningKey =
        Environment.GetEnvironmentVariable("TOKEN_SIGNING_KEY") is { Length: > 0 } key
            ? Encoding.UTF8.GetBytes(key)
            : RandomNumberGenerator.GetBytes(32);
    private static readonly string? AdminApiKey = Environment.GetEnvironmentVariable("ADMIN_API_KEY");

    [HttpPost("login")]
    public IActionResult Login([FromForm] string username, [FromForm] string password)
    {
        using var conn = new SqliteConnection(ConnectionString);
        conn.Open();

        // [ĐÃ SỬA 2] Câu SQL cố định; username đi riêng qua tham số @username.
        const string sql = "SELECT id, username, full_name, role, password_hash, salt FROM users " +
                           "WHERE username = @username";
        using var cmd = new SqliteCommand(sql, conn);
        cmd.Parameters.AddWithValue("@username", username);
        using var reader = cmd.ExecuteReader();
        if (!reader.Read() || !Database.VerifyPassword(password, reader.GetString(5), reader.GetString(4)))
            return Unauthorized(new { error = "Sai tên đăng nhập hoặc mật khẩu.", sql });

        var user = reader.GetString(1);
        return Ok(new { message = $"Xin chào {reader.GetString(2)}", role = reader.GetString(3),
                        token = SignToken(user), sql });
    }

    [HttpGet("users/search")]
    public IActionResult Search([FromQuery] string q = "")
    {
        using var conn = new SqliteConnection(ConnectionString);
        conn.Open();
        using var cmd = conn.CreateCommand();

        // [ĐÃ SỬA 2] Ký tự % nằm trong GIÁ TRỊ tham số, không nằm trong câu SQL.
        cmd.CommandText = "SELECT id, username, full_name, email, role FROM users " +
                          "WHERE username LIKE @pattern OR full_name LIKE @pattern";
        cmd.Parameters.AddWithValue("@pattern", "%" + q + "%");
        return Ok(new { sql = cmd.CommandText, rows = ReadRows(cmd) });
    }

    [HttpGet("admin/stats")]
    public IActionResult Stats([FromHeader(Name = "X-Api-Key")] string? apiKey)
    {
        if (string.IsNullOrEmpty(AdminApiKey) || apiKey is null ||
            !CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(apiKey), Encoding.UTF8.GetBytes(AdminApiKey)))
            return Unauthorized();
        using var conn = new SqliteConnection(ConnectionString);
        conn.Open();
        using var cmd = new SqliteCommand("SELECT COUNT(*) FROM users", conn);
        return Ok(new { totalUsers = cmd.ExecuteScalar() });
    }

    private static string SignToken(string username)
    {
        using var hmac = new HMACSHA256(TokenSigningKey);
        var signature = Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(username)));
        return $"{username}.{signature}";
    }

    private static List<object> ReadRows(SqliteCommand cmd)
    {
        var rows = new List<object>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
            rows.Add(new { id = reader.GetValue(0), username = reader.GetValue(1), fullName = reader.GetValue(2),
                           email = reader.GetValue(3), role = reader.GetValue(4) });
        return rows;
    }
}
