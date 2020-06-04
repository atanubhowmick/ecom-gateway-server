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
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import dev.atanu.ecom.gateway.constant.ErrorCode;
import dev.atanu.ecom.gateway.exception.GatewayException;

/**
 * A class to perform password-based AES encryption and decryption in CBC mode.
 * 256-bit AES encryption are being used which is permitted by the Java
 * runtime's jurisdiction policy files. <br>
 * {@link https://proandroiddev.com/security-best-practices-symmetric-encryption-with-aes-in-java-7616beaaade9}
 * <br>
 * {@link https://stackoverflow.com/questions/44878997/handling-of-iv-and-salt-in-java-encryption-and-decryption}
 * <br>
 * {@link https://stackoverflow.com/questions/992019/java-256-bit-aes-password-based-encryption}
 * 
 * @author Atanu Bhowmick
 *
 */
public class AESSecurityUtil {

	private AESSecurityUtil() {
		// Private constructor
	}

	/**
	 * Encrypt plain text using AES
	 * 
	 * @param plainText
	 * @param password
	 * @return cipher text
	 */
	public static String encrypt(String plainText, char[] password) {
		try {
			byte[] salt = getSalt();
			SecretKeySpec secretKeySpec = getSecretKeySpec(salt, password);

			// AES initialization
			Cipher cipher = Cipher.getInstance(SecurityConstant.AES_ENCRYPT_ALGORITHM);
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

			// Generate IV
			byte[] iv = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
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
			Cipher cipher = Cipher.getInstance(SecurityConstant.AES_ENCRYPT_ALGORITHM);
			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));
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
