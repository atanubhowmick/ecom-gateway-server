/**
 * 
 */
package dev.atanu.ecom.gateway.config;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
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
import org.springframework.util.StringUtils;

import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.IMap;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;

import dev.atanu.ecom.gateway.constant.ErrorCode;
import dev.atanu.ecom.gateway.constant.GatewayConstant;
import dev.atanu.ecom.gateway.dto.ErrorResponse;
import dev.atanu.ecom.gateway.dto.GatewayResponse;
import dev.atanu.ecom.gateway.dto.GenericResponse;
import dev.atanu.ecom.gateway.security.AESSecurityUtil;
import dev.atanu.ecom.gateway.security.RSASecurityUtil;
import dev.atanu.ecom.gateway.security.RandomStringGenerator;
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

	private static final Logger logger = LoggerFactory.getLogger(SecurityPostFilter.class);

	@Override
	public boolean shouldFilter() {
		return decryptRequest || encryptResponse;
	}

	@Override
	public Object run() throws ZuulException {
		RequestContext context = RequestContext.getCurrentContext();
		if (decryptRequest) {
			this.setPublicKey(context);
		}
		if (encryptResponse) {
			this.encryptResponse(context);
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
	 * Send public key to client application for request encryption. Will also be
	 * sending offset as unique identifier of public, private key pair to retrieve
	 * the private key from cache to decrypt the encrypted request.
	 * 
	 * <br>
	 * Http Header - publicKey <br>
	 * Http Header - signature
	 * 
	 * @param context
	 */
	private void setPublicKey(RequestContext context) {
		HttpServletResponse httpResponse = context.getResponse();
		try {
			SecurityKeyDetails keyDetails = RSASecurityUtil.generateKeys();
			IMap<String, SecurityKeyDetails> keyMap = hazelcastInstance.getMap(SecurityConstant.SECURITY_KEY_MAP);
			String randomString = RandomStringGenerator.getRandomString(SecurityConstant.OFFSET_LENGTH);
			while (keyMap.containsKey(randomString)) {
				randomString = RandomStringGenerator.getRandomString(SecurityConstant.OFFSET_LENGTH);
			}
			String offset = randomString;
			keyDetails.setOffset(offset);
			keyDetails.setSignature(RSASecurityUtil.sign(offset, keyDetails.getPrivateKeyString()));

			httpResponse.setHeader(GatewayConstant.HTTP_HEADER_SIGNATURE, keyDetails.getSignature());
			httpResponse.setHeader(GatewayConstant.HTTP_HEADER_PUBLIC_KEY, keyDetails.getPublicKeyString());
			keyMap.lock(offset);
			keyMap.put(offset, keyDetails, 2L, TimeUnit.HOURS);
			keyMap.unlock(offset);
		} catch (Exception e) {
			logger.error("Unable set public key in response header", e);
			this.sendErrorResponse(context, ErrorCode.GATEWAY_S001, HttpStatus.BAD_GATEWAY);
		}
	}

	/**
	 * Encrypt response with AES algorithm (Password based) and the password is
	 * encrypted with RSA algorithm. To encrypt the data, Public key is required
	 * from client application. And to verify the public key Signature is also
	 * required. So the public key, signature and identifier are expected in request
	 * headers. <br>
	 * Http Header - publicKey <br>
	 * Http Header - signature <br>
	 * Http Header - identifier
	 * 
	 * @param context
	 */
	private void encryptResponse(RequestContext context) {
		HttpServletRequest request = context.getRequest();
		HttpServletResponse response = context.getResponse();

		String publicKey = request.getHeader(GatewayConstant.HTTP_HEADER_PUBLIC_KEY);
		String signature = request.getHeader(GatewayConstant.HTTP_HEADER_SIGNATURE);
		String identifier = request.getHeader(GatewayConstant.HTTP_HEADER_IDENTIFIER);
		InputStream in = context.getResponseDataStream();

		logger.debug("Public Key from header: {}", publicKey);
		logger.debug("Signature from header : {}", signature);
		logger.debug("Identifier from header: {}", identifier);

		if (!StringUtils.isEmpty(publicKey) && !StringUtils.isEmpty(signature) && !StringUtils.isEmpty(identifier)
				&& null != in) {
			try {
				String body = StreamUtils.copyToString(in, StandardCharsets.UTF_8);
				boolean publicKeyVerified = RSASecurityUtil.verify(identifier, signature, publicKey);
				if (publicKeyVerified) {
					SecureRandom random = new SecureRandom();
					int len = Integer.max(SecurityConstant.MIN_PHRASE_LEN,
							random.nextInt(SecurityConstant.MAX_PHRASE_LEN));
					String key = RandomStringGenerator.getRandomString(len);
					String encryptedBody = AESSecurityUtil.encrypt(body, key.toCharArray());
					String encryptedKey = RSASecurityUtil.encrypt(key, publicKey);
					response.setHeader(GatewayConstant.HTTP_HEADER_PASS_PHRASE, encryptedKey);
					GatewayResponse gatewayResponse = new GatewayResponse(identifier, encryptedBody);
					context.setResponseBody(GatewayUtil.toJson(gatewayResponse));
				} else {
					logger.error("Unable to verify sign");
					this.sendErrorResponse(context, ErrorCode.GATEWAY_S005, HttpStatus.BAD_REQUEST);
				}
			} catch (Exception e) {
				logger.error("Unexcepted error occured", e);
				this.sendErrorResponse(context, ErrorCode.GATEWAY_E500, HttpStatus.INTERNAL_SERVER_ERROR);
			}
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
