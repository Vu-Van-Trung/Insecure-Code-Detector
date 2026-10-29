package demo.usermanager;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class UserManagerApplication {

    public static void main(String[] args) throws Exception {
        Database.initialize();
        System.out.println("Tai khoan demo: admin / admin123");
        SpringApplication.run(UserManagerApplication.class, args);
    }
}
