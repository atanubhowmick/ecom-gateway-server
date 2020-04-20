package com.atanu.spring.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;

import springfox.documentation.swagger2.annotations.EnableSwagger2;

/**
 * 
 * @author Atanu Bhowmick
 *
 */
@EnableZuulProxy
@EnableEurekaClient
@EnableSwagger2
@SpringBootApplication
public class GatewayServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(GatewayServerApplication.class, args);
	}

}
