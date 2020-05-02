/**
 * 
 */
package dev.atanu.ecom.gateway.constant;

/**
 * @author Atanu Bhowmick
 *
 */
public enum ErrorCode {

	GATEWAY_E001("Maximum hit limit reached"),
	GATEWAY_E002("Invalid Json"),

	GATEWAY_E500("Internal Server Error. Please try again later!");

	private String errorMsg;

	private ErrorCode(String errorMsg) {
		this.errorMsg = errorMsg;
	}

	public String getErrorMsg() {
		return errorMsg;
	}
}
