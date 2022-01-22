/**
 * 
 */
package dev.atanu.ecom.gateway.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import springfox.documentation.swagger.web.SwaggerResource;
import springfox.documentation.swagger.web.SwaggerResourcesProvider;

/**
 * https://stackoverflow.com/questions/44636575/swagger-consolidation-for-multiple-microservices
 * <br>
 * https://github.com/GnanaJeyam/microservice-patterns
 * 
 * @author Atanu Bhowmick
 *
 */
@Component
@Primary
public class SwaggerResourceConfiguration implements SwaggerResourcesProvider {

	@Override
	public List<SwaggerResource> get() {
		List<SwaggerResource> resources = new ArrayList<>();
		resources.add(getSwaggerResource("product-svc", "/product/v2/api-docs", "2.0"));
		resources.add(getSwaggerResource("cart-svc", "/cart/v2/api-docs", "2.0"));
		resources.add(getSwaggerResource("order-svc", "/order/v2/api-docs", "2.0"));
		resources.add(getSwaggerResource("payment-svc", "/payment/v2/api-docs", "2.0"));
		return resources;
	}

	/**
	 * Get Swagger Resource
	 * 
	 * @param name
	 * @param location
	 * @param version
	 * @return SwaggerResource
	 */
	private SwaggerResource getSwaggerResource(String name, String location, String version) {
		SwaggerResource resource = new SwaggerResource();
		resource.setName(name);
		resource.setLocation(location);
		resource.setSwaggerVersion(version);
		return resource;
	}

}
