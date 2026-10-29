// Demo: the same controller written safely.
using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;

public class AccountController : Controller
{
    private readonly string connectionString = Environment.GetEnvironmentVariable("DB_CONNECTION");

    [HttpGet("orders")]
    public IActionResult Orders([FromQuery] string customer)
    {
        using var conn = new SqlConnection(connectionString);
        var command = new SqlCommand("SELECT * FROM Orders WHERE Customer = @customer", conn);
        command.Parameters.AddWithValue("@customer", customer);
        return Ok(command.ExecuteReader());
    }

    [HttpGet("tools/ping")]
    public IActionResult Ping([FromQuery] string host)
    {
        if (!IPAddress.TryParse(host, out var address)) return BadRequest();
        var psi = new ProcessStartInfo("ping") { UseShellExecute = false };
        psi.ArgumentList.Add(address.ToString());
        Process.Start(psi);
        return Ok();
    }

    [HttpPost("profile")]
    public IActionResult Import()
    {
        var profile = JsonSerializer.Deserialize<Profile>(Request.Body);
        return Ok(profile);
    }

    public byte[] HashPassword(string password, byte[] salt)
    {
        return Rfc2898DeriveBytes.Pbkdf2(password, salt, 600_000, HashAlgorithmName.SHA256, 32);
    }

    [HttpGet("files")]
    public IActionResult Download([FromQuery] string name)
    {
        // Path.GetFileName keeps only the file name: "../../web.config" -> "web.config".
        return PhysicalFile(Path.Combine("/srv/files", Path.GetFileName(name)), "application/octet-stream");
    }

    [HttpGet("hello")]
    public IActionResult Hello([FromQuery] string name)
    {
        return Content("<h1>Hello " + WebUtility.HtmlEncode(name) + "</h1>", "text/html");
    }
}
