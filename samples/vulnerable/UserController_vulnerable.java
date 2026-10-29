// Demo: a Spring controller with typical Java vulnerabilities.
// INTENTIONALLY VULNERABLE - for local testing of Secure Code Analyzer only. Never deploy it.
// All credentials are FAKE.
package demo;

import java.io.ObjectInputStream;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.ResultSet;
import java.util.Random;
import javax.servlet.http.HttpServletRequest;

@RestController
public class UserController {
    private static final String DB_PASSWORD = "Adm1n!2024";            // JV008
    private Connection conn;

    @GetMapping("/users")
    public ResultSet findUser(@RequestParam("name") String name) throws Exception {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        return conn.createStatement().executeQuery(sql);                // JV002 (tainted)
    }

    @GetMapping("/ping")
    public void ping(HttpServletRequest request) throws Exception {
        String host = request.getParameter("host");
        Runtime.getRuntime().exec("ping -c 1 " + host);                // JV001 (tainted)
    }

    @PostMapping("/session")
    public Object restore(HttpServletRequest request) throws Exception {
        ObjectInputStream in = new ObjectInputStream(request.getInputStream());
        return in.readObject();                                          // JV003 (tainted)
    }

    public String hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");            // JV005
        return new String(md.digest(password.getBytes()));
    }

    public String createResetToken() {
        Random random = new Random();
        return Long.toHexString(random.nextLong());                      // JV007
    }

    @GetMapping("/files")
    public byte[] download(@RequestParam("name") String name) throws Exception {
        return java.nio.file.Files.readAllBytes(java.nio.file.Paths.get("/srv/files", name)); // JV011 (tainted)
    }

    @GetMapping("/hello")
    public String hello(@RequestParam("name") String name) {
        return "<h1>Hello " + name + "</h1>";                            // JV012 (tainted)
    }
}
