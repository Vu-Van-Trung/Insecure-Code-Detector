// Demo: an ASP.NET Core controller with typical C# vulnerabilities.
// INTENTIONALLY VULNERABLE - for local testing of Secure Code Analyzer only. Never deploy it.
// All credentials are FAKE.
using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Net;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;

public class AccountController : Controller
{
    private const string ConnectionString = "Server=db;Database=shop;User Id=sa;Password=Sh0pAdm1n!;"; // CS008

    [HttpGet("orders")]
    public IActionResult Orders([FromQuery] string customer)
    {
        using var conn = new SqlConnection(Environment.GetEnvironmentVariable("DB"));
        var command = new SqlCommand($"SELECT * FROM Orders WHERE Customer = '{customer}'", conn); // CS002
        return Ok(command.ExecuteReader());
    }

    [HttpGet("tools/ping")]
    public IActionResult Ping([FromQuery] string host)
    {
        Process.Start("cmd.exe", "/c ping -n 1 " + host);                // CS001
        return Ok();
    }

    [HttpPost("profile")]
    public IActionResult Import()
    {
        var formatter = new BinaryFormatter();
        var profile = formatter.Deserialize(Request.Body);               // CS003
        return Ok(profile);
    }

    public string HashPassword(string password)
    {
        using var md5 = MD5.Create();                                    // CS005
        return Convert.ToHexString(md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password)));
    }

    public void TrustEveryone()
    {
        ServicePointManager.ServerCertificateValidationCallback = (s, c, ch, e) => true; // CS009
    }
}
