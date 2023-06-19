/**
 * 
 */
package dev.atanu.ecom.gateway.config;

import java.util.Objects;
import java.util.concurrent.TimeUnit;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.netflix.zuul.filters.route.RibbonRoutingFilter;
import org.springframework.cloud.netflix.zuul.filters.support.FilterConstants;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.IMap;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;

import dev.atanu.ecom.gateway.constant.ErrorCode;
import dev.atanu.ecom.gateway.constant.GatewayConstant;
import dev.atanu.ecom.gateway.dto.ErrorResponse;
import dev.atanu.ecom.gateway.dto.GenericResponse;
import dev.atanu.ecom.gateway.util.GatewayUtil;

/**
 * @author Atanu Bhowmick
 *
 */
@Component
public class GatewayFilter extends ZuulFilter {

	@Autowired
	private HazelcastInstance hazelcastInstance;

	@Value("${api.max.hit.interval:1}")
	private long maxApiHitInterval;

	@Value("${api.max.hit.count:20}")
	private long maxApiHitCount;

	private static final Logger logger = LoggerFactory.getLogger(GatewayFilter.class);

	@Override
	public boolean shouldFilter() {
		RequestContext context = RequestContext.getCurrentContext();
		HttpServletRequest request = context.getRequest();
		String method = this.getVerb(request);
		return !(HttpMethod.GET.matches(method.toUpperCase()));
	}

	@Override
	public Object run() throws ZuulException {
		RequestContext context = RequestContext.getCurrentContext();
		this.limitApiHit(context);
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
		return 100;
	}

	/**
	 * @see RibbonRoutingFilter
	 * 
	 * @param request
	 * @return method
	 */
	private String getVerb(HttpServletRequest request) {
		String method = request.getMethod();
		if (method == null) {
			return HttpMethod.GET.name();
		}
		return method;
	}

	/**
	 * @param context
	 */
	private void limitApiHit(RequestContext context) {
		HttpServletRequest request = context.getRequest();
		String method = this.getVerb(request);
		String servideId = (String) context.get(FilterConstants.SERVICE_ID_KEY);
		String requestURI = (String) context.get(FilterConstants.REQUEST_URI_KEY);

		// Retrieve username for logged-in scenario
		String username = "";

		StringBuilder builder = new StringBuilder(username);
		builder.append(GatewayConstant.HYPHEN);
		builder.append(method);
		builder.append(GatewayConstant.HYPHEN);
		builder.append(servideId);
		builder.append(GatewayConstant.HYPHEN);
		builder.append(requestURI);
		String mapKey = builder.toString();

		IMap<String, Integer> apiMap = hazelcastInstance.getMap(GatewayConstant.API_HIT_MAP_KEY);
		Integer hitCount = apiMap.get(mapKey);
		logger.debug("Map Key: {} and hit count: {}", mapKey, hitCount);

		if (Objects.nonNull(hitCount) && hitCount.intValue() >= maxApiHitCount) {
			context.setSendZuulResponse(false);
			context.setResponseBody(this.generateErrorResponse(ErrorCode.GATEWAY_E001, HttpStatus.TOO_MANY_REQUESTS));
			HttpServletResponse httpResponse = context.getResponse();
			if (httpResponse != null) {
				httpResponse.setContentType(MediaType.APPLICATION_JSON_VALUE);
			}
		} else {
			if (Objects.isNull(hitCount)) {
				hitCount = 1;
				apiMap.lock(mapKey);
				apiMap.put(mapKey, hitCount, maxApiHitInterval, TimeUnit.MINUTES);
				apiMap.unlock(mapKey);
			} else {
				hitCount += 1;
				apiMap.lock(mapKey);
				apiMap.put(mapKey, hitCount);
				apiMap.unlock(mapKey);
			}
		}
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
