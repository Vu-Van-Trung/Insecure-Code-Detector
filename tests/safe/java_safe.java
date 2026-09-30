// Safe counterpart of java_vulnerable.java.
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.List;
import java.util.Random;
import javax.crypto.Cipher;
import javax.servlet.http.HttpServletRequest;

public class UserService {
    private static final String DB_PASSWORD = System.getenv("DB_PASSWORD");
    private static final int PASSWORD_MIN_LENGTH = 12;
    private static final String API_KEY_HEADER = "X-API-Key";

    public void run(HttpServletRequest request, Connection conn) throws Exception {
        String host = request.getParameter("host");
        new ProcessBuilder("ping", "-c", "1", host).start();
        new ProcessBuilder(List.of("nslookup", host)).start();

        String id = request.getParameter("id");
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, id);
        ps.executeQuery();

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    }

    public String generateResetToken() {
        SecureRandom random = new SecureRandom();
        return Long.toHexString(random.nextLong());
    }

    public int rollDice() {
        return new Random().nextInt(6) + 1;
    }
}
