/**
 * 
 */
package dev.atanu.ecom.gateway.config;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

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
import org.springframework.util.StringUtils;

import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.IMap;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;

import dev.atanu.ecom.gateway.constant.ErrorCode;
import dev.atanu.ecom.gateway.constant.GatewayConstant;
import dev.atanu.ecom.gateway.dto.ErrorResponse;
import dev.atanu.ecom.gateway.dto.GatewayRequest;
import dev.atanu.ecom.gateway.dto.GenericResponse;
import dev.atanu.ecom.gateway.security.AESSecurityUtil;
import dev.atanu.ecom.gateway.security.RSASecurityUtil;
import dev.atanu.ecom.gateway.security.SecurityConstant;
import dev.atanu.ecom.gateway.security.SecurityKeyDetails;
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

	private static final Logger logger = LoggerFactory.getLogger(SecurityPreFilter.class);

	@Override
	public boolean shouldFilter() {
		return decryptRequest;
	}

	@Override
	public Object run() throws ZuulException {
		RequestContext context = RequestContext.getCurrentContext();
		if (decryptRequest) {
			this.decryptRequest(context);
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
	 * Request is encrypted AES algorithm(Password based) and the password of AES
	 * are encrypted with RSA (Hybrid RSA algorithm). The public key was generated
	 * and shared with previous response. Decrypt the request with private key
	 * whichs is present in cache and remove the key from cache. The encrypted
	 * password is expected in request header and offset in request body.
	 * 
	 * <br>
	 * Http Header - passPhrase <br>
	 * Http Header - requestEncrypted (boolean)
	 * 
	 * @param context
	 */
	private void decryptRequest(RequestContext context) {
		HttpServletRequest request = context.getRequest();
		String requestEncrypted = request.getHeader(GatewayConstant.HTTP_HEADER_REQUEST_ENCRYPTED);
		String phrase = request.getHeader(GatewayConstant.HTTP_HEADER_PASS_PHRASE);

		try {
			if (GatewayConstant.TRUE.equalsIgnoreCase(requestEncrypted) && !StringUtils.isEmpty(phrase)) {
				InputStream in = (InputStream) context.get(GatewayConstant.REQUEST_ENTITY);
				if (in == null) {
					in = request.getInputStream();
				}
				if (in != null) {
					String body = StreamUtils.copyToString(in, StandardCharsets.UTF_8);
					logger.info("Request Body : {}", body);
					GatewayRequest gatewayRequest = GatewayUtil.toObject(body, GatewayRequest.class);
					IMap<String, SecurityKeyDetails> keyMap = hazelcastInstance
							.getMap(SecurityConstant.SECURITY_KEY_MAP);
					if (keyMap.containsKey(gatewayRequest.getOffset())) {
						SecurityKeyDetails keyDetails = keyMap.get(gatewayRequest.getOffset());
						keyMap.remove(gatewayRequest.getOffset());

						String requestBody = AESSecurityUtil.decrypt(body,
								RSASecurityUtil.decrypt(phrase, keyDetails.getPrivateKeyString()).toCharArray());
						context.set(GatewayConstant.REQUEST_ENTITY,
								new ByteArrayInputStream(requestBody.getBytes(StandardCharsets.UTF_8)));
					} else {
						logger.error("Key details expired from cache");
						this.sendErrorResponse(context, ErrorCode.GATEWAY_E003, HttpStatus.FORBIDDEN);
					}
				}
			}
		} catch (Exception e) {
			logger.error("Unable to decrypt request body", e);
			this.sendErrorResponse(context, ErrorCode.GATEWAY_S003, HttpStatus.BAD_REQUEST);
		}
	}

	/**
	 * Generate error response with error code and error message
	 * 
	 * @param context
	 * @param errorCode
	 * @param httpStatus
	 */
	private void sendErrorResponse(RequestContext context, ErrorCode errorCode, HttpStatus httpStatus) {
		ErrorResponse errorResponse = new ErrorResponse(errorCode.name(), errorCode.getErrorMsg(), httpStatus);
		GenericResponse<?> response = new GenericResponse<>();
		response.setError(errorResponse);

		HttpServletResponse httpResponse = context.getResponse();
		context.setSendZuulResponse(false);
		httpResponse.setContentType(MediaType.APPLICATION_JSON_VALUE);
		context.setResponseBody(GatewayUtil.toJson(response));
	}
}
