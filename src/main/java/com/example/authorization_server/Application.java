package com.example.authorization_server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(excludeName = "")
public class Application {

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

}
