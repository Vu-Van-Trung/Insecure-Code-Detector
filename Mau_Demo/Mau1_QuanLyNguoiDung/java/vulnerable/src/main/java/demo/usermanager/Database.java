package demo.usermanager;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HexFormat;

public final class Database {

    static final String DB_URL = "jdbc:sqlite:users.db";

    private static final String[][] SEED_USERS = {
        {"admin", "admin123", "Quản trị viên", "admin@demo.local", "admin"},
        {"nguyenvana", "matkhau1", "Nguyễn Văn A", "vana@demo.local", "user"},
        {"tranthib", "123456", "Trần Thị B", "thib@demo.local", "user"},
        {"levanc", "levanc@2024", "Lê Văn C", "vanc@demo.local", "user"},
    };

    private Database() {
    }

    // [LỖ HỔNG 3 - Weak Cryptography] MD5 nhanh, không salt -> dễ bị bẻ bằng bảng cầu vồng.
    public static String hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        return HexFormat.of().formatHex(md5.digest(password.getBytes(StandardCharsets.UTF_8)));
    }

    public static void initialize() throws SQLException, NoSuchAlgorithmException {
        try (Connection conn = DriverManager.getConnection(DB_URL); Statement stmt = conn.createStatement()) {
            stmt.executeUpdate("DROP TABLE IF EXISTS users");
            stmt.executeUpdate("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, "
                    + "password_hash TEXT, full_name TEXT, email TEXT, role TEXT)");
            try (PreparedStatement insert = conn.prepareStatement(
                    "INSERT INTO users (username, password_hash, full_name, email, role) VALUES (?, ?, ?, ?, ?)")) {
                for (String[] u : SEED_USERS) {
                    insert.setString(1, u[0]);
                    insert.setString(2, hashPassword(u[1]));
                    insert.setString(3, u[2]);
                    insert.setString(4, u[3]);
                    insert.setString(5, u[4]);
                    insert.executeUpdate();
                }
            }
        }
    }
}
