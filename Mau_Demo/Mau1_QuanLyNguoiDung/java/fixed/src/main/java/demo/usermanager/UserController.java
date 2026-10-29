// Mẫu 1 - Website quản lý người dùng (Java / Spring Boot) - BẢN ĐÃ SỬA.
//
// Đối chiếu với ../vulnerable/.../UserController.java:
//   [1] Hardcoded Secret  -> đọc khóa từ biến môi trường, không có thì sinh ngẫu nhiên
//   [2] SQL Injection     -> PreparedStatement với placeholder ?, giá trị gắn bằng setString()
//   [3] Weak Cryptography -> PBKDF2WithHmacSHA256 + salt (xem Database.java), so sánh thời gian hằng
package demo.usermanager;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
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

    // [ĐÃ SỬA 1] Secret nằm ngoài mã nguồn (biến môi trường / Vault / Spring Cloud Config).
    private static final byte[] TOKEN_SIGNING_KEY = loadSigningKey();
    private static final String ADMIN_API_KEY = System.getenv("ADMIN_API_KEY");

    private static byte[] loadSigningKey() {
        String fromEnv = System.getenv("TOKEN_SIGNING_KEY");
        if (fromEnv != null && !fromEnv.isEmpty()) {
            return fromEnv.getBytes(StandardCharsets.UTF_8);
        }
        byte[] random = new byte[32];
        new SecureRandom().nextBytes(random);
        return random;
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestParam String username,
                                                     @RequestParam String password) throws Exception {
        // [ĐÃ SỬA 2] Câu SQL cố định; username đi riêng qua tham số.
        String sql = "SELECT id, username, full_name, role, password_hash, salt FROM users WHERE username = ?";
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, username);
            try (ResultSet rs = stmt.executeQuery()) {
                if (!rs.next() || !Database.verifyPassword(password, rs.getString("salt"),
                        rs.getString("password_hash"))) {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(body("error", "Sai tên đăng nhập hoặc mật khẩu.", "sql", sql));
                }
                String user = rs.getString("username");
                return ResponseEntity.ok(body("message", "Xin chào " + rs.getString("full_name"),
                        "role", rs.getString("role"), "token", signToken(user), "sql", sql));
            }
        }
    }

    @GetMapping("/users/search")
    public ResponseEntity<Map<String, Object>> search(@RequestParam(defaultValue = "") String q)
            throws SQLException {
        // [ĐÃ SỬA 2] Ký tự % nằm trong GIÁ TRỊ tham số, không nằm trong câu SQL.
        String sql = "SELECT id, username, full_name, email, role FROM users "
                + "WHERE username LIKE ? OR full_name LIKE ?";
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            String pattern = "%" + q + "%";
            stmt.setString(1, pattern);
            stmt.setString(2, pattern);
            try (ResultSet rs = stmt.executeQuery()) {
                return ResponseEntity.ok(body("sql", sql, "rows", readRows(rs)));
            }
        }
    }

    @GetMapping("/admin/stats")
    public ResponseEntity<Map<String, Object>> stats(
            @RequestHeader(value = "X-Api-Key", required = false) String apiKey) throws SQLException {
        if (ADMIN_API_KEY == null || ADMIN_API_KEY.isEmpty() || apiKey == null
                || !MessageDigest.isEqual(apiKey.getBytes(StandardCharsets.UTF_8),
                                          ADMIN_API_KEY.getBytes(StandardCharsets.UTF_8))) {
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
        mac.init(new SecretKeySpec(TOKEN_SIGNING_KEY, "HmacSHA256"));
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
