// Testbench: ASP.NET Core controller with mixed C# vulnerabilities.
// INTENTIONALLY VULNERABLE - for local testing of Secure Code Analyzer only. Never deploy it.
// All credentials are FAKE. Expected findings are marked with "EXPECT: <rule>".
using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.CodeAnalysis.CSharp.Scripting;
using Newtonsoft.Json;

public class ReportController : Controller
{
    private const string JwtSigningKey = "q8Zr2Lm9Xv4Tn7Bc1Wd6Yh3Kp0Fs5Ga";  // EXPECT: CS008
    private readonly string _smtpPassword = "Mail#Srv2025";            // EXPECT: CS008
    private readonly SqlConnection _conn = new SqlConnection("Server=.;Integrated Security=true");

    [HttpGet("reports")]
    public IActionResult Find([FromQuery] string author, [FromQuery] string year)
    {
        string filter = "Author = '" + author + "'";
        string sql = "SELECT * FROM Reports WHERE " + filter + " AND Year = " + year;
        var cmd = new SqlCommand(sql, _conn);
        return Ok(cmd.ExecuteReader());                                  // EXPECT: CS002 (multi-hop)
    }

    [HttpGet("reports/safe")]
    public IActionResult FindSafe([FromQuery] string author)
    {
        var cmd = new SqlCommand("SELECT * FROM Reports WHERE Author = @a", _conn);
        cmd.Parameters.AddWithValue("@a", author);
        return Ok(cmd.ExecuteReader());                                  // safe: no finding
    }

    [HttpPost("reports/render")]
    public IActionResult Render([FromForm] string template)
    {
        var psi = new ProcessStartInfo("wkhtmltopdf", template + " out.pdf");
        Process.Start(psi);                                              // EXPECT: CS001
        return Ok();
    }

    [HttpPost("reports/formula")]
    public async System.Threading.Tasks.Task<IActionResult> Formula([FromBody] string expr)
    {
        var result = await CSharpScript.EvaluateAsync(expr);            // EXPECT: CS004
        return Ok(result);
    }

    [HttpPost("reports/import")]
    public IActionResult Import()
    {
        var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All }; // EXPECT: CS003
        var body = new StreamReader(Request.Body).ReadToEnd();
        return Ok(JsonConvert.DeserializeObject(body, settings));
    }

    public string Fingerprint(byte[] data)
    {
        using var sha1 = SHA1.Create();                                  // EXPECT: CS005
        return Convert.ToBase64String(sha1.ComputeHash(data));
    }

    public byte[] Encrypt(byte[] plain, byte[] key)
    {
        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;                                       // EXPECT: CS006
        aes.Key = key;
        return aes.CreateEncryptor().TransformFinalBlock(plain, 0, plain.Length);
    }

    public string ApiToken()
    {
        var rnd = new Random();
        var sb = new StringBuilder();
        for (int i = 0; i < 32; i++) sb.Append((char)('a' + rnd.Next(26))); // EXPECT: CS007
        return sb.ToString();
    }

    public string SafeApiToken()
    {
        return Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)); // safe: no finding
    }

    public HttpClient InsecureClient()
    {
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator // EXPECT: CS009
        };
        return new HttpClient(handler);
    }
}
