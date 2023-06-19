/**
 * 
 */
package dev.atanu.ecom.gateway.security;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import dev.atanu.ecom.gateway.constant.ErrorCode;
import dev.atanu.ecom.gateway.exception.GatewayException;

/**
 * A class to perform password-based AES encryption and decryption in GCM mode.
 * 256-bit AES encryption are being used
 * 
 * @author Atanu Bhowmick
 *
 */
public class AESGCMSecurityUtil {

	private AESGCMSecurityUtil() {
		// Private constructor
	}

	/**
	 * Encrypt plain text using AES GCM No Padding
	 * 
	 * @param plainText
	 * @param password
	 * @return cipher text
	 */
	public static String encrypt(String plainText, char[] password) {
		try {
			byte[] salt = getSalt();
			SecretKeySpec secretKeySpec = getSecretKeySpec(salt, password);

			// GCM Parameters
			final byte[] nonce = getNonce();
			GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(SecurityConstant.GCM_PARAM_SPEC_LEN, nonce);

			// AES initialization
			Cipher cipher = Cipher.getInstance(SecurityConstant.AES_GCM_ENCRYPT_ALGORITHM);
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);

			// Generate IV
			byte[] iv = gcmParameterSpec.getIV();
			byte[] encryptedText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

			// Publish salt, iv and cipher text
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			outputStream.write(salt);
			outputStream.write(iv);
			outputStream.write(encryptedText);

			// Deleting sensitive information
			Arrays.fill(salt, (byte) 0);
			Arrays.fill(password, '0');

			return Base64.getEncoder().encodeToString(outputStream.toByteArray());
		} catch (Exception e) {
			throw new GatewayException(ErrorCode.GATEWAY_S002.name(), ErrorCode.GATEWAY_S002.getErrorMsg(), e);
		}
	}

	/**
	 * Decrypt the cipher text usin AES
	 * 
	 * @param cipherText
	 * @param password
	 * @return Decrypted Text
	 */
	public static String decrypt(String cipherText, char[] password) {
		byte[] cipherBytes = Base64.getDecoder().decode(cipherText);
		try {
			int len = SecurityConstant.AES_SALT_LENGTH + SecurityConstant.AES_IV_LENGTH;
			byte[] salt = Arrays.copyOfRange(cipherBytes, 0, SecurityConstant.AES_SALT_LENGTH);
			byte[] iv = Arrays.copyOfRange(cipherBytes, SecurityConstant.AES_SALT_LENGTH, len);
			byte[] ct = Arrays.copyOfRange(cipherBytes, len, cipherBytes.length);

			SecretKeySpec secretKeySpec = getSecretKeySpec(salt, password);

			// decrypt the message
			Cipher cipher = Cipher.getInstance(SecurityConstant.AES_GCM_ENCRYPT_ALGORITHM);
			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new GCMParameterSpec(SecurityConstant.GCM_PARAM_SPEC_LEN, iv));
			byte[] decyrptTextBytes = cipher.doFinal(ct);

			// Deleting sensitive information
			Arrays.fill(salt, (byte) 0);
			Arrays.fill(password, '0');

			return new String(decyrptTextBytes, StandardCharsets.UTF_8);
		} catch (Exception e) {
			throw new GatewayException(ErrorCode.GATEWAY_S003.name(), ErrorCode.GATEWAY_S003.getErrorMsg(), e);
		}
	}

	/**
	 * Generate salt dynamically with random number
	 * 
	 * @return salt
	 */
	private static byte[] getSalt() {
		SecureRandom random = new SecureRandom();
		byte[] bytes = new byte[SecurityConstant.AES_SALT_LENGTH];
		random.nextBytes(bytes);
		return bytes;
	}

	/**
	 * Generate nonce dynamically with random number
	 * 
	 * @return nonce
	 */
	private static byte[] getNonce() {
		SecureRandom random = new SecureRandom();
		byte[] bytes = new byte[SecurityConstant.AES_NONCE_LENGTH];
		random.nextBytes(bytes);
		return bytes;
	}

	/**
	 * Generate SecretKeySpec using the combination of salt and password
	 * 
	 * @param salt
	 * @param password
	 * @return SecretKeySpec
	 */
	private static SecretKeySpec getSecretKeySpec(byte[] salt, char[] password) {
		try {
			SecretKeyFactory skf = SecretKeyFactory.getInstance(SecurityConstant.SECRET_KEY_FACTORY_ALGORITHM);
			PBEKeySpec spec = new PBEKeySpec(password, salt, SecurityConstant.AES_ITERATIONS,
					SecurityConstant.AES_KEY_LENGTH);
			SecretKey secretKey = skf.generateSecret(spec);
			return new SecretKeySpec(secretKey.getEncoded(), SecurityConstant.ENCRYPTION_AES);
		} catch (Exception e) {
			throw new GatewayException(ErrorCode.GATEWAY_S001.name(), ErrorCode.GATEWAY_S001.getErrorMsg(), e);
		}
	}
}
