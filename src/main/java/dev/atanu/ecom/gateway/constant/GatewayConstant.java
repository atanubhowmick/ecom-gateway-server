/**
 * 
 */
package dev.atanu.ecom.gateway.constant;

/**
 * Class for all the gateway constants
 * 
 * @author Atanu Bhowmick
 *
 */
public class GatewayConstant {

	private GatewayConstant() {
		// Default Constructor
	}
	
	public static final String EMPTY_STRING		 							= "";
	public static final String HYPHEN		 								= "-";
	public static final String TRUE		 									= "true";
	public static final String FALSE		 								= "false";
	
	// HTTP Header Constants
	public static final String HTTP_HEADER_PASS_PHRASE 						= "passPhrase";
	public static final String HTTP_HEADER_PUBLIC_KEY						= "publicKey";
	public static final String HTTP_HEADER_SIGNATURE						= "signature";
	public static final String HTTP_HEADER_IDENTIFIER						= "identifier";
	public static final String HTTP_HEADER_REQUEST_ENCRYPTED				= "requestEncrypted";
	public static final String HTTP_HEADER_RESPONSE_ENCRYPTED				= "responseEncrypted";
	public static final String REQUEST_ENTITY 								= "requestEntity";
	
	public static final String API_HIT_MAP_KEY 								= "ECOM_GATEWAY_HIT_LIMIT_MAP";
	
}
