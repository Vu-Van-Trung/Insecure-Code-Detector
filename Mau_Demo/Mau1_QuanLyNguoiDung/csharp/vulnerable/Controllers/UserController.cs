// Mẫu 1 - Website quản lý người dùng (C# / ASP.NET Core) - BẢN CÓ LỖ HỔNG.
// CHỈ DÙNG ĐỂ DEMO CÔNG CỤ PHÂN TÍCH. KHÔNG TRIỂN KHAI RA MÔI TRƯỜNG THẬT.
//
// Lỗ hổng được cài sẵn (tương đương bản Python):
//   [1] Hardcoded Secret   (CWE-798) - khóa ký token, API key quản trị
//   [2] SQL Injection      (CWE-89)  - đăng nhập và tìm kiếm ghép chuỗi SQL
//   [3] Weak Cryptography  (CWE-328) - băm mật khẩu bằng MD5, không có salt
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

    // [LỖ HỔNG 1 - Hardcoded Secret] Lộ mã nguồn = lộ khóa: giả mạo token, gọi API quản trị.
    private const string TokenSigningKey = "Qm9hJ3vX8kP2rT7wZ5nB1cL6dF4gH0sY";
    private const string AdminApiKey = "sk_live_51HxDemoAdminKey9f8e7d6c5b4a3";

    [HttpPost("login")]
    public IActionResult Login([FromForm] string username, [FromForm] string password)
    {
        using var conn = new SqliteConnection(ConnectionString);
        conn.Open();

        // [LỖ HỔNG 2 - SQL Injection] username (source: [FromForm]) được nối thẳng vào câu SQL.
        // Thử: username = admin' --     password = bất kỳ
        var sql = "SELECT id, username, full_name, role FROM users WHERE username = '" + username +
                  "' AND password_hash = '" + Database.HashPassword(password) + "'";
        using var cmd = new SqliteCommand(sql, conn);
        try
        {
            using var reader = cmd.ExecuteReader();
            if (!reader.Read())
                return Unauthorized(new { error = "Sai tên đăng nhập hoặc mật khẩu.", sql });

            var user = reader.GetString(1);
            return Ok(new { message = $"Xin chào {reader.GetString(2)}", role = reader.GetString(3),
                            token = SignToken(user), sql });
        }
        catch (SqliteException ex)
        {
            return BadRequest(new { error = ex.Message, sql });
        }
    }

    [HttpGet("users/search")]
    public IActionResult Search([FromQuery] string q = "")
    {
        using var conn = new SqliteConnection(ConnectionString);
        conn.Open();
        using var cmd = conn.CreateCommand();

        // [LỖ HỔNG 2 - SQL Injection] Chuỗi nội suy $"..." đưa từ khóa vào CommandText.
        // Thử: %' UNION SELECT id, username, password_hash, email, role FROM users --
        cmd.CommandText = $"SELECT id, username, full_name, email, role FROM users " +
                          $"WHERE username LIKE '%{q}%' OR full_name LIKE '%{q}%'";
        try
        {
            return Ok(new { sql = cmd.CommandText, rows = ReadRows(cmd) });
        }
        catch (SqliteException ex)
        {
            return BadRequest(new { error = ex.Message, sql = cmd.CommandText });
        }
    }

    [HttpGet("admin/stats")]
    public IActionResult Stats([FromHeader(Name = "X-Api-Key")] string? apiKey)
    {
        if (apiKey != AdminApiKey)
            return Unauthorized();
        using var conn = new SqliteConnection(ConnectionString);
        conn.Open();
        using var cmd = new SqliteCommand("SELECT COUNT(*) FROM users", conn);
        return Ok(new { totalUsers = cmd.ExecuteScalar() });
    }

    private static string SignToken(string username)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(TokenSigningKey));
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
