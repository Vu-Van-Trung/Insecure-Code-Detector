package demo.usermanager;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Base64;
import java.util.HexFormat;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public final class Database {

    static final String DB_URL = "jdbc:sqlite:users.db";
    private static final int ITERATIONS = 600_000;
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final String[][] SEED_USERS = {
        {"admin", "Quản trị viên", "admin@demo.local", "admin"},
        {"nguyenvana", "Nguyễn Văn A", "vana@demo.local", "user"},
        {"tranthib", "Trần Thị B", "thib@demo.local", "user"},
        {"levanc", "Lê Văn C", "vanc@demo.local", "user"},
    };

    private Database() {
    }

    // [ĐÃ SỬA 3] PBKDF2-HMAC-SHA256 chậm có chủ đích + salt ngẫu nhiên cho từng người dùng.
    public static String hashPassword(String password, byte[] salt) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, 256);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return HexFormat.of().formatHex(factory.generateSecret(spec).getEncoded());
        } finally {
            spec.clearPassword();
        }
    }

    public static boolean verifyPassword(String password, String saltHex, String expectedHex)
            throws GeneralSecurityException {
        byte[] actual = HexFormat.of().parseHex(hashPassword(password, HexFormat.of().parseHex(saltHex)));
        return MessageDigest.isEqual(actual, HexFormat.of().parseHex(expectedHex));
    }

    /** Tạo bảng và dữ liệu mẫu; trả về mật khẩu demo (từ DEMO_PASSWORD hoặc sinh ngẫu nhiên). */
    public static String initialize() throws SQLException, GeneralSecurityException {
        String demoPassword = System.getenv("DEMO_PASSWORD");
        if (demoPassword == null || demoPassword.isEmpty()) {
            byte[] random = new byte[9];
            RANDOM.nextBytes(random);
            demoPassword = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
        }
        try (Connection conn = DriverManager.getConnection(DB_URL); Statement stmt = conn.createStatement()) {
            stmt.executeUpdate("DROP TABLE IF EXISTS users");
            stmt.executeUpdate("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, "
                    + "password_hash TEXT, salt TEXT, full_name TEXT, email TEXT, role TEXT)");
            try (PreparedStatement insert = conn.prepareStatement("INSERT INTO users "
                    + "(username, password_hash, salt, full_name, email, role) VALUES (?, ?, ?, ?, ?, ?)")) {
                for (String[] u : SEED_USERS) {
                    byte[] salt = new byte[16];
                    RANDOM.nextBytes(salt);
                    insert.setString(1, u[0]);
                    insert.setString(2, hashPassword(demoPassword, salt));
                    insert.setString(3, HexFormat.of().formatHex(salt));
                    insert.setString(4, u[1]);
                    insert.setString(5, u[2]);
                    insert.setString(6, u[3]);
                    insert.executeUpdate();
                }
            }
        }
        return demoPassword;
    }
}
