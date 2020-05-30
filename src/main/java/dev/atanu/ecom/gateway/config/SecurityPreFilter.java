/**
 * 
 */
package dev.atanu.ecom.gateway.config;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.netflix.zuul.filters.support.FilterConstants;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.StreamUtils;

import com.hazelcast.core.HazelcastInstance;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;

import dev.atanu.ecom.gateway.constant.ErrorCode;
import dev.atanu.ecom.gateway.dto.ErrorResponse;
import dev.atanu.ecom.gateway.dto.GenericResponse;
import dev.atanu.ecom.gateway.util.GatewayUtil;

/**
 * @author Atanu Bhowmick
 *
 */
@Component
public class SecurityPreFilter extends ZuulFilter {

	@Autowired
	private HazelcastInstance hazelcastInstance;

	@Value("${decrypt.request}")
	private boolean decryptRequest;

	@Value("${encrypt.response}")
	private boolean encryptResponse;

	private static final Logger logger = LoggerFactory.getLogger(SecurityPreFilter.class);

	@Override
	public boolean shouldFilter() {
		return decryptRequest;
	}

	@Override
	public Object run() throws ZuulException {
		RequestContext context = RequestContext.getCurrentContext();
		try {
			if(decryptRequest) {
				this.decryptRequest(context);
			}
		} catch (IOException e) {
			logger.error("Exception occured..", e);
		}
		return null;
	}

	@Override
	public String filterType() {
		return FilterConstants.PRE_TYPE;
	}

	@Override
	public int filterOrder() {
		// Any number must not be conflicting with existing filter order
		// Look into RibbonRoutingFilter for more information
		return 101;
	}

	/**
	 * @param context
	 * @throws IOException
	 */
	private void decryptRequest(RequestContext context) throws IOException {
		HttpServletRequest request = context.getRequest();
		InputStream in = request.getInputStream();
		if (in == null) {
			in = request.getInputStream();
		}
		String body = StreamUtils.copyToString(in, StandardCharsets.UTF_8);
		logger.info("Request Body : {}", body);

	}

	/**
	 * 
	 * @param errorCode
	 * @param httpStatus
	 * @return String
	 */
	private String generateErrorResponse(ErrorCode errorCode, HttpStatus httpStatus) {
		ErrorResponse errorResponse = new ErrorResponse(errorCode.name(), errorCode.getErrorMsg(), httpStatus);
		GenericResponse<?> response = new GenericResponse<>();
		response.setError(errorResponse);
		return GatewayUtil.toJson(response);
	}
}
