// Safe counterpart of csharp_vulnerable.cs.
using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;

public class AccountController : Controller
{
    private readonly string connectionString = Environment.GetEnvironmentVariable("DB_CONNECTION");
    private const int PasswordMinLength = 12;

    public IActionResult Find([FromQuery] string name, SqlConnection conn)
    {
        var command = new SqlCommand("SELECT * FROM Users WHERE Name = @name", conn);
        command.Parameters.AddWithValue("@name", name);

        var input = Console.ReadLine();
        var psi = new ProcessStartInfo("ping") { UseShellExecute = false };
        psi.ArgumentList.Add(input);
        Process.Start(psi);

        var profile = JsonSerializer.Deserialize<Profile>(Request.Body);
        var sha = SHA256.Create();
        var aes = Aes.Create();
        return Ok();
    }

    private string CreateResetToken()
    {
        return Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    }

    private int RollDice()
    {
        return new Random().Next(1, 7);
    }
}
