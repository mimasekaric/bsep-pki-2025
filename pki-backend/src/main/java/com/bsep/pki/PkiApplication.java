package com.bsep.pki;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class PkiApplication {

	public static void main(String[] args) {
		SpringApplication.run(PkiApplication.class, args);
	}

}
