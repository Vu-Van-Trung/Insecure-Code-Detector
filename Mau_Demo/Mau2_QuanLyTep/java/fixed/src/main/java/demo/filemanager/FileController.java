// Mẫu 2 - Website quản lý tệp (Java / Spring Boot) - BẢN ĐÃ SỬA.
//
// Đối chiếu với ../vulnerable/.../FileController.java:
//   [1] Path Traversal    -> new File(name).getName() chỉ giữ tên tệp (sanitizer) + kiểm tra đường dẫn
//                            sau khi chuẩn hóa vẫn nằm trong storageDir và là tệp thường
//   [2] Command Injection -> bỏ hẳn cmd.exe: lấy thông tin tệp bằng Files.size / getLastModifiedTime
//
// Chạy:  mvn spring-boot:run   ->  http://127.0.0.1:5005
package demo.filemanager;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/files")
public class FileController {

    private static final DateTimeFormatter TIME_FORMAT =
            DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss").withZone(ZoneId.systemDefault());

    private final Path storageDir = Paths.get("..", "..", "storage").toAbsolutePath().normalize();

    /** Trả về đường dẫn an toàn bên trong storageDir, hoặc 404. */
    private Path safeStoragePath(String rawName) {
        String name = new File(rawName).getName();          // "../secret/config.txt" -> "config.txt"
        Path path = storageDir.resolve(name).normalize();
        if (name.isEmpty() || !path.startsWith(storageDir) || !Files.isRegularFile(path)) {   // lớp chặn thứ hai
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        return path;
    }

    @GetMapping
    public Map<String, Object> list() throws IOException {
        try (Stream<Path> files = Files.list(storageDir)) {
            List<String> names = files.map(p -> p.getFileName().toString()).sorted().toList();
            return body("version", "ĐÃ SỬA", "files", names);
        }
    }

    @GetMapping("/view")
    public Map<String, Object> view(@RequestParam String name) throws IOException {
        // [ĐÃ SỬA 1] Tên tệp đi qua sanitizer + kiểm tra trước khi chạm tới Files.readString().
        Path path = safeStoragePath(name);
        String content = Files.readString(path, StandardCharsets.UTF_8);
        return body("name", path.getFileName().toString(), "path", path.toString(), "content", content);
    }

    @GetMapping("/download")
    public ResponseEntity<Resource> download(@RequestParam String name) {
        // [ĐÃ SỬA 1] Cùng hàm kiểm tra với /view.
        Path path = safeStoragePath(name);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + path.getFileName() + "\"")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(new FileSystemResource(path));
    }

    @GetMapping("/info")
    public Map<String, Object> info(@RequestParam String name) throws IOException {
        // [ĐÃ SỬA 2] Không tạo tiến trình / shell nữa -> không còn chỗ để chèn lệnh.
        Path path = safeStoragePath(name);
        String output = "Tên tệp      : " + path.getFileName() + "\n"
                + "Kích thước   : " + Files.size(path) + " byte\n"
                + "Sửa lần cuối : " + TIME_FORMAT.format(Files.getLastModifiedTime(path).toInstant());
        return body("name", path.getFileName().toString(), "command", "Files.size() - không dùng shell",
                "output", output);
    }

    /** Map giữ thứ tự khóa: body("k1", v1, "k2", v2, ...). */
    static Map<String, Object> body(Object... pairs) {
        Map<String, Object> map = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            map.put((String) pairs[i], pairs[i + 1]);
        }
        return map;
    }
}
