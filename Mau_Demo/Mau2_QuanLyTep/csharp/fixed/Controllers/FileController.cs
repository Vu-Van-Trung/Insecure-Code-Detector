// Mẫu 2 - Website quản lý tệp (C# / ASP.NET Core) - BẢN ĐÃ SỬA.
//
// Đối chiếu với ../vulnerable/Controllers/FileController.cs:
//   [1] Path Traversal    -> Path.GetFileName() chỉ giữ lại tên tệp (sanitizer) + kiểm tra đường dẫn
//                            sau khi GetFullPath vẫn nằm trong _storageDir và tệp có tồn tại
//   [2] Command Injection -> bỏ hẳn cmd.exe: lấy thông tin tệp bằng FileInfo
//
// Luồng taint sau khi sửa:
//   [FromQuery] name -> Path.GetFileName(name) [SANITIZER] -> tên sạch -> File.ReadAllText(path)
//
// Chạy:  dotnet run   ->  http://127.0.0.1:5003
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

    /// <summary>Trả về đường dẫn an toàn bên trong _storageDir, hoặc null.</summary>
    private string? SafeStoragePath(string? rawName)
    {
        var fileName = Path.GetFileName(rawName ?? "");          // "../secret/config.txt" -> "config.txt"
        if (string.IsNullOrEmpty(fileName))
            return null;
        var path = Path.GetFullPath(Path.Combine(_storageDir, fileName));
        // Lớp chặn thứ hai: đường dẫn cuối cùng phải nằm trong thư mục storage.
        if (!path.StartsWith(_storageDir + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
            || !System.IO.File.Exists(path))
            return null;
        return path;
    }

    [HttpGet]
    public IActionResult List()
    {
        var files = Directory.GetFiles(_storageDir).Select(Path.GetFileName).OrderBy(n => n);
        return Ok(new { version = "ĐÃ SỬA", files });
    }

    [HttpGet("view")]
    public IActionResult View([FromQuery] string name)
    {
        // [ĐÃ SỬA 1] Tên tệp đi qua sanitizer trước khi chạm tới File.ReadAllText().
        var path = SafeStoragePath(name);
        if (path is null)
            return NotFound(new { name, error = "Không tìm thấy tệp." });
        return Ok(new { name = Path.GetFileName(path), path, content = System.IO.File.ReadAllText(path) });
    }

    [HttpGet("download")]
    public IActionResult Download([FromQuery] string name)
    {
        var path = SafeStoragePath(name);
        if (path is null)
            return NotFound(new { name, error = "Không tìm thấy tệp." });
        return PhysicalFile(path, "application/octet-stream", Path.GetFileName(path));
    }

    [HttpGet("info")]
    public IActionResult Info([FromQuery] string name)
    {
        // [ĐÃ SỬA 2] Không gọi cmd.exe nữa -> không còn chỗ để chèn lệnh.
        var path = SafeStoragePath(name);
        if (path is null)
            return NotFound(new { name, error = "Không tìm thấy tệp." });
        var info = new FileInfo(path);
        var output = $"Tên tệp      : {info.Name}\n"
                   + $"Kích thước   : {info.Length} byte\n"
                   + $"Sửa lần cuối : {info.LastWriteTime:dd/MM/yyyy HH:mm:ss}";
        return Ok(new { name = info.Name, command = "FileInfo - không dùng shell", output });
    }
}
