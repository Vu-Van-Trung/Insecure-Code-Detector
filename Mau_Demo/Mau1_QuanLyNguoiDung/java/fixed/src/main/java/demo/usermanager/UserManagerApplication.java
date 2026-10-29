package demo.usermanager;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class UserManagerApplication {

    public static void main(String[] args) throws Exception {
        String demoPassword = Database.initialize();
        System.out.println("Tai khoan demo: admin / " + demoPassword + "   (dat bien DEMO_PASSWORD de co dinh)");
        SpringApplication.run(UserManagerApplication.class, args);
    }
}
