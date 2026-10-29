// Mẫu 2 - Website quản lý tệp (C# / ASP.NET Core) - BẢN CÓ LỖ HỔNG.
// CHỈ DÙNG ĐỂ DEMO CÔNG CỤ PHÂN TÍCH. KHÔNG TRIỂN KHAI RA MÔI TRƯỜNG THẬT.
//
// Lỗ hổng được cài sẵn (tương đương bản Python ../../python/vulnerable/app.py):
//   [1] Path Traversal     (CWE-22) - /api/files/view và /download ghép tên tệp từ người dùng vào đường dẫn
//   [2] Command Injection  (CWE-78) - /api/files/info đưa tên tệp vào lệnh cmd.exe /c
//
// Luồng taint (source -> propagation -> sink):
//   [FromQuery] name -> path = Path.Combine(StorageDir, name) -> File.ReadAllText(path) / PhysicalFile(path)
//   [FromQuery] name -> path -> arguments = "/c dir \"" + path + "\""  -> new ProcessStartInfo(...)
//
// Chạy:  dotnet run   ->  http://127.0.0.1:5003
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace FileManager.Controllers;

[ApiController]
[Route("api/files")]
public class FileController : ControllerBase
{
    private readonly string _storageDir;

    public FileController(IWebHostEnvironment env)
    {
        _storageDir = Path.GetFullPath(Path.Combine(env.ContentRootPath, "..", "..", "storage"));
    }

    [HttpGet]
    public IActionResult List()
    {
        var files = Directory.GetFiles(_storageDir).Select(Path.GetFileName).OrderBy(n => n);
        return Ok(new { version = "CÓ LỖ HỔNG", files });
    }

    [HttpGet("view")]
    public IActionResult View([FromQuery] string name)          // SOURCE: dữ liệu từ URL
    {
        var path = Path.Combine(_storageDir, name);              // PROPAGATION: taint lan sang path

        // [LỖ HỔNG 1 - Path Traversal] Không kiểm tra "..\" hay đường dẫn tuyệt đối.
        // Path.Combine còn bỏ qua _storageDir nếu name là đường dẫn tuyệt đối (C:\Windows\win.ini).
        // Thử: /api/files/view?name=../secret/config.txt
        try
        {
            var content = System.IO.File.ReadAllText(path);       // SINK
            return Ok(new { name, path = Path.GetFullPath(path), content });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return NotFound(new { name, error = ex.Message });
        }
    }

    [HttpGet("download")]
    public IActionResult Download([FromQuery] string name)
    {
        // [LỖ HỔNG 1 - Path Traversal] Tải được mọi tệp mà tiến trình web đọc được.
        // Thử: /api/files/download?name=../csharp/vulnerable/Program.cs
        var path = Path.GetFullPath(Path.Combine(_storageDir, name));
        return PhysicalFile(path, "application/octet-stream", Path.GetFileName(path));   // SINK
    }

    [HttpGet("info")]
    public IActionResult Info([FromQuery] string name)
    {
        var path = Path.Combine(_storageDir, name);
        var arguments = "/c dir \"" + path + "\"";

        // [LỖ HỔNG 2 - Command Injection] Chuỗi lệnh chứa dữ liệu người dùng được chạy qua cmd.exe.
        // Thử: /api/files/info?name=bao_cao.txt" & whoami & echo "
        var psi = new ProcessStartInfo("cmd.exe", arguments)       // SINK
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        using var process = Process.Start(psi)!;
        var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        process.WaitForExit();
        return Ok(new { name, command = "cmd.exe " + arguments, output });
    }
}
