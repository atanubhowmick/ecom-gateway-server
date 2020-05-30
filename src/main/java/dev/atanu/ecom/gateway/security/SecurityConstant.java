/**
 * 
 */
package dev.atanu.ecom.gateway.security;

/**
 * @author Atanu Bhowmick
 *
 */
public class SecurityConstant {
	
	private SecurityConstant() {
	}
	
	public static final String ENCRYPTION_ALGORITHM_RSA						= "RSA";
	public static final String ENCRYPTION_PADDING_RSA						= "RSA/ECB/PKCS1Padding";
	public static final String DECRYPTION_PADDING_RSA						= "RSA/ECB/PKCS1Padding";
	public static final String DECRYPTION_SIGNATURE_SHA						= "SHA256withRSA";
}
