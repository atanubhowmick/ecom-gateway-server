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
	GATEWAY_E003("Session timeout"),
	
	// Security Error Code
	GATEWAY_S001("Unable to generate Security Keys"),
	GATEWAY_S002("Unable to encrypt the given text/file"),
	GATEWAY_S003("Unable to decrypt the given text/file"),
	GATEWAY_S004("Unable to sign"),
	GATEWAY_S005("Unable to verify sign"),
	
	
	GATEWAY_E500("Internal Server Error. Please try again later!");

	private String errorMsg;

	private ErrorCode(String errorMsg) {
		this.errorMsg = errorMsg;
	}

	public String getErrorMsg() {
		return errorMsg;
	}
}
