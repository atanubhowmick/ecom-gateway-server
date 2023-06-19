/**
 * 
 */
package dev.atanu.ecom.gateway.exception;

import org.springframework.http.HttpStatus;

/**
 * @author Atanu Bhowmick
 *
 */
public class GatewayException extends RuntimeException {

	private static final long serialVersionUID = 3102842828601606582L;

	private final String errorCode;
	private final String errorMessage;
	private HttpStatus httpStatus = HttpStatus.INTERNAL_SERVER_ERROR;

	public GatewayException(String errorCode, String errorMessage) {
		this.errorCode = errorCode;
		this.errorMessage = errorMessage;
	}
	
	public GatewayException(String errorCode, String errorMessage, HttpStatus httpStatus) {
		this.errorCode = errorCode;
		this.errorMessage = errorMessage;
		this.httpStatus = httpStatus;
	}

	public GatewayException(String errorCode, String errorMessage, Throwable ex) {
		super(ex);
		this.errorCode = errorCode;
		this.errorMessage = errorMessage;
	}

	public GatewayException(String errorCode, String errorMessage, HttpStatus httpStatus, Throwable ex) {
		super(ex);
		this.errorCode = errorCode;
		this.errorMessage = errorMessage;
		this.httpStatus = httpStatus;
	}

	@Override
	public String getMessage() {
		String msg = "";
		if (null != this.errorMessage) {
			msg = this.errorMessage;
		} else {
			msg = super.getMessage();
		}
		return msg;
	}

	public String getErrorCode() {
		return errorCode;
	}

	public String getErrorMessage() {
		return errorMessage;
	}

	public HttpStatus getHttpStatus() {
		return httpStatus;
	}
}
