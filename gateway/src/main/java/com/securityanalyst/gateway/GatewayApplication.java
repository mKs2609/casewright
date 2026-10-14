package com.securityanalyst.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.securityanalyst.gateway.common.RequiredSettingsCheck;

@SpringBootApplication
public class GatewayApplication {

	public static void main(String[] args) {
		SpringApplication app = new SpringApplication(GatewayApplication.class);
		app.addListeners(new RequiredSettingsCheck());
		app.run(args);
	}

}
