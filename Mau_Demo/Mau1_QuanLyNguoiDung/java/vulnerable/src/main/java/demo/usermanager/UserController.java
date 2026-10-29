// Mẫu 1 - Website quản lý người dùng (Java / Spring Boot) - BẢN CÓ LỖ HỔNG.
// CHỈ DÙNG ĐỂ DEMO CÔNG CỤ PHÂN TÍCH. KHÔNG TRIỂN KHAI RA MÔI TRƯỜNG THẬT.
//
// Lỗ hổng được cài sẵn (tương đương bản Python và C#):
//   [1] Hardcoded Secret   (CWE-798) - khóa ký token, API key quản trị
//   [2] SQL Injection      (CWE-89)  - đăng nhập và tìm kiếm ghép chuỗi SQL rồi chạy bằng Statement
//   [3] Weak Cryptography  (CWE-328) - băm mật khẩu bằng MD5, không có salt (xem Database.java)
package demo.usermanager;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class UserController {

    private static final String DB_URL = Database.DB_URL;

    // [LỖ HỔNG 1 - Hardcoded Secret] Lộ mã nguồn = lộ khóa: giả mạo token, gọi API quản trị.
    private static final String TOKEN_SIGNING_KEY = "Qm9hJ3vX8kP2rT7wZ5nB1cL6dF4gH0sY";
    private static final String ADMIN_API_KEY = "sk_live_51HxDemoAdminKey9f8e7d6c5b4a3";

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestParam String username,
                                                     @RequestParam String password) throws Exception {
        // [LỖ HỔNG 2 - SQL Injection] username (source: @RequestParam) được nối thẳng vào câu SQL.
        // Thử: username = admin' --     password = bất kỳ
        String sql = "SELECT id, username, full_name, role FROM users WHERE username = '" + username
                + "' AND password_hash = '" + Database.hashPassword(password) + "'";
        try (Connection conn = DriverManager.getConnection(DB_URL);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {                       // SINK
            if (!rs.next()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(body("error", "Sai tên đăng nhập hoặc mật khẩu.", "sql", sql));
            }
            String user = rs.getString("username");
            return ResponseEntity.ok(body("message", "Xin chào " + rs.getString("full_name"),
                    "role", rs.getString("role"), "token", signToken(user), "sql", sql));
        } catch (SQLException ex) {
            return ResponseEntity.badRequest().body(body("error", ex.getMessage(), "sql", sql));
        }
    }

    @GetMapping("/users/search")
    public ResponseEntity<Map<String, Object>> search(@RequestParam(defaultValue = "") String q) {
        // [LỖ HỔNG 2 - SQL Injection] Từ khóa tìm kiếm được ghép vào mệnh đề LIKE.
        // Thử: %' UNION SELECT id, username, password_hash, email, role FROM users --
        String sql = "SELECT id, username, full_name, email, role FROM users "
                + "WHERE username LIKE '%" + q + "%' OR full_name LIKE '%" + q + "%'";
        try (Connection conn = DriverManager.getConnection(DB_URL);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {                       // SINK
            return ResponseEntity.ok(body("sql", sql, "rows", readRows(rs)));
        } catch (SQLException ex) {
            return ResponseEntity.badRequest().body(body("error", ex.getMessage(), "sql", sql));
        }
    }

    @GetMapping("/admin/stats")
    public ResponseEntity<Map<String, Object>> stats(
            @RequestHeader(value = "X-Api-Key", required = false) String apiKey) throws SQLException {
        if (!ADMIN_API_KEY.equals(apiKey)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        try (Connection conn = DriverManager.getConnection(DB_URL);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM users")) {
            rs.next();
            return ResponseEntity.ok(body("totalUsers", rs.getInt(1)));
        }
    }

    private static String signToken(String username) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(TOKEN_SIGNING_KEY.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return username + "." + HexFormat.of().formatHex(mac.doFinal(username.getBytes(StandardCharsets.UTF_8)));
    }

    static List<Map<String, Object>> readRows(ResultSet rs) throws SQLException {
        List<Map<String, Object>> rows = new ArrayList<>();
        while (rs.next()) {
            rows.add(body("id", rs.getObject(1), "username", rs.getObject(2), "fullName", rs.getObject(3),
                    "email", rs.getObject(4), "role", rs.getObject(5)));
        }
        return rows;
    }

    /** Map giữ thứ tự khóa, chấp nhận giá trị null: body("k1", v1, "k2", v2, ...). */
    static Map<String, Object> body(Object... pairs) {
        Map<String, Object> map = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            map.put((String) pairs[i], pairs[i + 1]);
        }
        return map;
    }
}
