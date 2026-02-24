package com.authenticationsystem.auth_api;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import io.github.cdimascio.dotenv.Dotenv;

@SpringBootApplication
public class AuthApiApplication {

	public static void main(String[] args) {
		
	    Dotenv dotenv = Dotenv.configure()
                .ignoreIfMissing()
                .load();

        System.setProperty("JWT_SECURITY_KEY", dotenv.get("JWT_SECURITY_KEY"));
        System.setProperty("JWT_EXPIRATION", dotenv.get("JWT_EXPIRATION"));
		
        SpringApplication.run(AuthApiApplication.class, args);
		
	}

}
