package com.authx;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
 
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

@SpringBootApplication
public class AuthxApplication {
    public static void main(String[] args) {
        SpringApplication.run(AuthxApplication.class, args);
    }

    @Bean
    CommandLineRunner runner(Environment env) {
        return args -> {
            System.out.println("DB_URL       = " + env.getProperty("DB_URL"));
            System.out.println("DB_USER      = " + env.getProperty("DB_USER"));
            System.out.println("DB_PASSWORD  = " + env.getProperty("DB_PASSWORD"));
        };
    }
}
