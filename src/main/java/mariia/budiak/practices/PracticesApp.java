package mariia.budiak.practices;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import java.security.Security;

@EnableCaching
@EnableSwagger2
@SpringBootApplication
public class PracticesApp {

    public static void main(String[] args) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        SpringApplication.run(PracticesApp.class, args);
    }
}
