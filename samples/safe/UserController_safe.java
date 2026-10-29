// Demo: the same controller written safely.
package demo;

import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import javax.servlet.http.HttpServletRequest;

@RestController
public class UserController {
    private static final String DB_PASSWORD = System.getenv("DB_PASSWORD");
    private Connection conn;

    @GetMapping("/users")
    public ResultSet findUser(@RequestParam("name") String name) throws Exception {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, name);
        return ps.executeQuery();
    }

    @GetMapping("/ping")
    public void ping(HttpServletRequest request) throws Exception {
        String host = request.getParameter("host");
        if (!host.matches("[a-zA-Z0-9.-]+")) {
            throw new IllegalArgumentException("invalid host");
        }
        new ProcessBuilder("ping", "-c", "1", host).start();
    }

    public String createResetToken() {
        SecureRandom random = new SecureRandom();
        return Long.toHexString(random.nextLong());
    }

    @GetMapping("/files")
    public byte[] download(@RequestParam("name") String name) throws Exception {
        // FilenameUtils.getName keeps only the file name: "../../etc/passwd" -> "passwd".
        String fileName = org.apache.commons.io.FilenameUtils.getName(name);
        return java.nio.file.Files.readAllBytes(java.nio.file.Paths.get("/srv/files", fileName));
    }

    @GetMapping("/hello")
    public String hello(@RequestParam("name") String name) {
        return "<h1>Hello " + org.springframework.web.util.HtmlUtils.htmlEscape(name) + "</h1>";
    }
}
