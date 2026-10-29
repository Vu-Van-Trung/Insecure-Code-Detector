// Mẫu 2 - Website quản lý tệp (Java / Spring Boot) - BẢN CÓ LỖ HỔNG.
// CHỈ DÙNG ĐỂ DEMO CÔNG CỤ PHÂN TÍCH. KHÔNG TRIỂN KHAI RA MÔI TRƯỜNG THẬT.
//
// Lỗ hổng được cài sẵn (tương đương bản Python và C#):
//   [1] Path Traversal     (CWE-22) - /api/files/view và /download ghép tên tệp từ người dùng vào đường dẫn
//   [2] Command Injection  (CWE-78) - /api/files/info đưa tên tệp vào lệnh cmd.exe /c
//
// Luồng taint (source -> propagation -> sink):
//   @RequestParam name -> path = storageDir.resolve(name) -> Files.readString(path) / FileSystemResource(path)
//   @RequestParam name -> path -> command = "dir \"" + path + "\"" -> new ProcessBuilder("cmd.exe", "/c", command)
//
// Chạy:  mvn spring-boot:run   ->  http://127.0.0.1:5005
package demo.filemanager;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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

@RestController
@RequestMapping("/api/files")
public class FileController {

    // Chạy từ thư mục java/vulnerable -> kho tệp nằm ở ../../storage
    private final Path storageDir = Paths.get("..", "..", "storage").toAbsolutePath().normalize();

    @GetMapping
    public Map<String, Object> list() throws IOException {
        try (Stream<Path> files = Files.list(storageDir)) {
            List<String> names = files.map(p -> p.getFileName().toString()).sorted().toList();
            return body("version", "CÓ LỖ HỔNG", "files", names);
        }
    }

    @GetMapping("/view")
    public ResponseEntity<Map<String, Object>> view(@RequestParam String name) {   // SOURCE
        Path path = storageDir.resolve(name);                                      // PROPAGATION

        // [LỖ HỔNG 1 - Path Traversal] Không kiểm tra "../" hay đường dẫn tuyệt đối.
        // Path.resolve() còn trả về chính name nếu name là đường dẫn tuyệt đối (C:\Windows\win.ini).
        // Thử: /api/files/view?name=../secret/config.txt
        try {
            String content = Files.readString(path, StandardCharsets.UTF_8);         // SINK
            return ResponseEntity.ok(body("name", name, "path", path.normalize().toString(), "content", content));
        } catch (IOException ex) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(body("name", name, "error", ex.toString()));
        }
    }

    @GetMapping("/download")
    public ResponseEntity<Resource> download(@RequestParam String name) {
        // [LỖ HỔNG 1 - Path Traversal] Tải được mọi tệp mà tiến trình web đọc được.
        // Thử: /api/files/download?name=../java/vulnerable/pom.xml
        Path path = storageDir.resolve(name).normalize();
        Resource resource = new FileSystemResource(path);                            // SINK
        if (!resource.exists()) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + path.getFileName() + "\"")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(resource);
    }

    @GetMapping("/info")
    public Map<String, Object> info(@RequestParam String name) throws IOException, InterruptedException {
        Path path = storageDir.resolve(name);
        String command = "dir \"" + path + "\"";

        // [LỖ HỔNG 2 - Command Injection] Chuỗi lệnh chứa dữ liệu người dùng được chạy qua cmd.exe.
        // Thử: /api/files/info?name=bao_cao.txt" & whoami & echo "
        Process process = new ProcessBuilder("cmd.exe", "/c", command)              // SINK
                .redirectErrorStream(true)
                .start();
        String output = new String(process.getInputStream().readAllBytes());
        process.waitFor();
        return body("name", name, "command", "cmd.exe /c " + command, "output", output);
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
