// Intentionally vulnerable test fixture: C# rules CS001 - CS009. Never compile or run this file.
using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Net;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;

public class AccountController : Controller
{
    private const string ConnectionString = "Server=db;Database=app;User Id=sa;Password=Sup3rS3cret!;"; // expect: CS008
    private const string ApiKey = "a8f5f167f44f4964e6c998dee827110c"; // expect: CS008

    public IActionResult Find([FromQuery] string name, SqlConnection conn)
    {
        var sql = $"SELECT * FROM Users WHERE Name = '{name}'";
        var command = new SqlCommand(sql, conn); // expect: CS002

        var input = Console.ReadLine();
        Process.Start("cmd.exe", "/c dir " + input); // expect: CS001

        var formatter = new BinaryFormatter();
        var profile = formatter.Deserialize(Request.Body); // expect: CS003

        var result = CSharpScript.EvaluateAsync(Request.Query["expr"]); // expect: CS004

        var md5 = MD5.Create(); // expect: CS005
        var des = DES.Create(); // expect: CS006

        ServicePointManager.ServerCertificateValidationCallback = (s, cert, chain, errors) => true; // expect: CS009
        return Ok();
    }

    private string CreateResetToken()
    {
        var random = new Random();
        return random.Next().ToString("x"); // expect: CS007
    }
}
