// Testbench: Spring service with mixed Java vulnerabilities.
// INTENTIONALLY VULNERABLE - for local testing of Secure Code Analyzer only. Never deploy it.
// All credentials are FAKE. Expected findings are marked with "EXPECT: <rule>".
package testbench;

import java.io.ObjectInputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.Random;
import javax.crypto.Cipher;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.servlet.http.HttpServletRequest;

@RestController
public class OrderService {
    private static final String API_SECRET = "ghp_9fK2mQx7LpR4tW8zYb1NcV6hJ3dS0aEuGi5o"; // EXPECT: JV008
    private String password = "SuperS3cret!2025";                                         // EXPECT: JV008
    private Connection conn;

    @GetMapping("/orders")
    public Object list(@RequestParam("status") String status, @RequestParam("sort") String sort) throws Exception {
        String base = "SELECT * FROM orders WHERE status = '" + status + "'";
        String sql = base + " ORDER BY " + sort;
        Statement st = conn.createStatement();
        return st.executeQuery(sql);                                    // EXPECT: JV002 (multi-hop taint)
    }

    @GetMapping("/orders/safe")
    public Object listSafe(@RequestParam("status") String status) throws Exception {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM orders WHERE status = ?");
        ps.setString(1, status);
        return ps.executeQuery();                                       // safe: no finding
    }

    @PostMapping("/export")
    public void export(HttpServletRequest request) throws Exception {
        String fmt = request.getParameter("format");
        String[] cmd = {"/bin/sh", "-c", "export-tool --format " + fmt};
        new ProcessBuilder(cmd).start();                                // EXPECT: JV001
    }

    @PostMapping("/import")
    public Object importOrders(HttpServletRequest request) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
        return ois.readObject();                                        // EXPECT: JV003
    }

    @GetMapping("/discount")
    public Object discount(@RequestParam("rule") String rule) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("javascript");
        return engine.eval(rule);                                       // EXPECT: JV004
    }

    public byte[] checksum(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-1").digest(data);         // EXPECT: JV005
    }

    public byte[] encryptCard(byte[] card, javax.crypto.SecretKey key) throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");          // EXPECT: JV006
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(card);
    }

    public String legacyEncrypt() throws Exception {
        Cipher c = Cipher.getInstance("DES");                           // EXPECT: JV006
        return c.getAlgorithm();
    }

    public String otpCode() {
        Random rnd = new Random();
        return String.format("%06d", rnd.nextInt(1000000));             // EXPECT: JV007
    }

    public String safeOtpCode() {
        SecureRandom rnd = new SecureRandom();
        return String.format("%06d", rnd.nextInt(1000000));             // safe: no finding
    }

    public void trustAllHosts() {
        HostnameVerifier allowAll = (hostname, session) -> true;
        HttpsURLConnection.setDefaultHostnameVerifier(allowAll);       // EXPECT: JV009
    }
}
