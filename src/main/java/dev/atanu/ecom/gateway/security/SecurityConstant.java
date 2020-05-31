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
	
	public static final String ENCRYPTION_RSA								= "RSA";
	public static final int RSA_KEY_LENGTH									= 2048;
	public static final int OFFSET_LENGTH									= 64;
	
	public static final String RSA_ENCRYPT_ALGORITHM						= "RSA/ECB/PKCS1Padding";
	public static final String DECRYPTION_PADDING_RSA						= "RSA/ECB/PKCS1Padding";
	public static final String RSA_SIGNATURE_SHA							= "SHA256withRSA";
	
	// AES Encryption Constants
	public static final String ENCRYPTION_AES								= "AES";
	public static final int AES_SALT_LENGTH									= 20;
	public static final int AES_IV_LENGTH 									= 16;
	public static final int AES_KEY_LENGTH 									= 256;
	public static final int AES_ITERATIONS 									= 65536;
	public static final String AES_ENCRYPT_ALGORITHM 						= "AES/CBC/PKCS5Padding";
	public static final String SECRET_KEY_FACTORY_ALGORITHM 				= "PBKDF2WithHmacSHA1";
	
	public static final String SECURITY_KEY_MAP								= "GATEWAY_SECURITY_KEY_MAP";
}
