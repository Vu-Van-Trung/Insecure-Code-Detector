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

    public void download(HttpServletRequest request, javax.servlet.http.HttpServletResponse response) throws Exception {
        String name = org.apache.commons.io.FilenameUtils.getName(request.getParameter("file"));
        byte[] data = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get("/srv/files", name));
        String other = new java.io.File(request.getParameter("other")).getName();
        new java.io.File("/srv/uploads", other).delete();

        String query = request.getParameter("q");
        response.getWriter().println("<p>Results for " + HtmlUtils.htmlEscape(query) + "</p>");
        java.io.PrintWriter log = new java.io.PrintWriter(new java.io.FileWriter("/var/log/app.log"));
        log.println("search: " + HtmlUtils.htmlEscape(query));
    }

    @GetMapping("/hello")
    public String hello(@RequestParam("name") String name) {
        return "<h1>Hello " + Encode.forHtml(name) + "</h1>";
    }

    @GetMapping("/profile")
    public String profile(@RequestParam("tab") String tab) {
        return "profile/" + tab;
    }
}
