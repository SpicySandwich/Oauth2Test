package com.backendauthorizationserver;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

@SpringBootApplication

public class BackendAuthorizationServerApplication {


	public static void main(String[] args) {
	SpringApplication.run(BackendAuthorizationServerApplication.class, args);


//		ServerProperties serverProperties = new ServerProperties();
//		int port = serverProperties.getPort();
//		System.out.println("port "+ port);
	}


}
