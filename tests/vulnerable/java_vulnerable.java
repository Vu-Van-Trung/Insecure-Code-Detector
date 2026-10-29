// Intentionally vulnerable test fixture: Java rules JV001 - JV012. Never compile or run this file.
import java.io.ObjectInputStream;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.Statement;
import java.util.Random;
import javax.crypto.Cipher;
import javax.servlet.http.HttpServletRequest;

public class UserService {
    private static final String DB_PASSWORD = "Adm1n!2024"; // expect: JV008
    private static final String API_KEY = "a8f5f167f44f4964e6c998dee827110c"; // expect: JV008

    public void run(HttpServletRequest request, Connection conn) throws Exception {
        String host = request.getParameter("host");
        Runtime.getRuntime().exec("ping -c 1 " + host); // expect: JV001
        new ProcessBuilder("sh", "-c", "nslookup " + host).start(); // expect: JV001

        String id = request.getParameter("id");
        String query = "SELECT * FROM users WHERE id = " + id;
        Statement st = conn.createStatement();
        st.executeQuery(query); // expect: JV002

        ObjectInputStream in = new ObjectInputStream(request.getInputStream());
        Object session = in.readObject(); // expect: JV003

        javax.script.ScriptEngine engine = new javax.script.ScriptEngineManager().getEngineByName("js");
        engine.eval(request.getParameter("expr")); // expect: JV004

        MessageDigest md = MessageDigest.getInstance("MD5"); // expect: JV005
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding"); // expect: JV006
    }

    public String generateResetToken() {
        Random random = new Random();
        return Long.toHexString(random.nextLong()); // expect: JV007
    }

    public void connect(javax.net.ssl.HttpsURLConnection connection) {
        connection.setHostnameVerifier((hostname, session) -> true); // expect: JV009
    }

    public void download(HttpServletRequest request, javax.servlet.http.HttpServletResponse response) throws Exception {
        String name = request.getParameter("file");
        byte[] data = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get("/srv/files", name)); // expect: JV011
        java.io.File upload = new java.io.File("/srv/uploads", name);
        upload.delete(); // expect: JV011

        String query = request.getParameter("q");
        response.getWriter().println("<p>Results for " + query + "</p>"); // expect: JV012
    }

    @GetMapping("/hello")
    public String hello(@RequestParam("name") String name) {
        return "<h1>Hello " + name + "</h1>"; // expect: JV012
    }
}
