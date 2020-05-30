/**
 * 
 */
package dev.atanu.ecom.gateway.config;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.netflix.zuul.filters.support.FilterConstants;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.StreamUtils;

import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.IMap;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;

import dev.atanu.ecom.gateway.constant.ErrorCode;
import dev.atanu.ecom.gateway.dto.ErrorResponse;
import dev.atanu.ecom.gateway.dto.GenericResponse;
import dev.atanu.ecom.gateway.security.RSASecurityUtil;
import dev.atanu.ecom.gateway.security.SecurityConstant;
import dev.atanu.ecom.gateway.security.SecurityKeyDetails;
import dev.atanu.ecom.gateway.util.GatewayUtil;

/**
 * @author Atanu Bhowmick
 *
 */
@Component
public class SecurityPostFilter extends ZuulFilter {

	@Autowired
	private HazelcastInstance hazelcastInstance;

	@Value("${decrypt.request}")
	private boolean decryptRequest;

	@Value("${encrypt.response}")
	private boolean encryptResponse;

	private String offset = null;

	private static final Logger logger = LoggerFactory.getLogger(SecurityPostFilter.class);

	@Override
	public boolean shouldFilter() {
		return decryptRequest || encryptResponse;
	}

	@Override
	public Object run() throws ZuulException {
		RequestContext context = RequestContext.getCurrentContext();
		try {
			if (decryptRequest) {
				this.setPublicKey(context);
			}
			if (encryptResponse) {
				this.encryptResponse(context);
			}
		} catch (IOException e) {
			logger.error("Exception occured..", e);
		}
		return null;
	}

	@Override
	public String filterType() {
		return FilterConstants.POST_TYPE;
	}

	@Override
	public int filterOrder() {
		// Any number must not be conflicting with existing filter order
		// Look into RibbonRoutingFilter for more information
		return 102;
	}

	/**
	 * 
	 * @param context
	 */
	private void setPublicKey(RequestContext context) {
		HttpServletResponse httpResponse = context.getResponse();
		try {
			SecurityKeyDetails keyDetails = RSASecurityUtil.generateKeys();
			offset = keyDetails.getOffset();
			IMap<String, SecurityKeyDetails> keyMap = hazelcastInstance.getMap(SecurityConstant.SECURITY_KEY_MAP);
			while (keyMap.containsKey(offset)) {
				keyDetails = RSASecurityUtil.generateKeys();
			}
			httpResponse.setHeader("signature", keyDetails.getSignature());
			httpResponse.setHeader("publicKey", keyDetails.getPublicKeyString());
			keyMap.lock(offset);
			keyMap.put(offset, keyDetails, 2L, TimeUnit.HOURS);
			keyMap.unlock(offset);
		} catch (Exception e) {
			logger.error("Unable set public key in response header", e);
			context.setSendZuulResponse(false);
			context.setResponseBody(this.generateErrorResponse(ErrorCode.GATEWAY_S001, HttpStatus.BAD_GATEWAY));
			httpResponse.setContentType(MediaType.APPLICATION_JSON_VALUE);
		}
	}

	/**
	 * @param context
	 * @throws IOException
	 */
	private void encryptResponse(RequestContext context) throws IOException {
		HttpServletRequest request = context.getRequest();
		InputStream in = (InputStream) context.get("requestEntity");
		if (in == null) {
			in = request.getInputStream();
		}
		String body = StreamUtils.copyToString(in, StandardCharsets.UTF_8);
		logger.info("Request Body : {}", body);
		context.set("requestEntity", new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));
	}

	/**
	 * Generate error response with error code and error message
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
