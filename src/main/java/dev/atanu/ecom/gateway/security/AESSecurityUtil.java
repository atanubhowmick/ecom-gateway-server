/**
 * 
 */
package dev.atanu.ecom.gateway.security;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import dev.atanu.ecom.gateway.exception.GatewayException;

/**
 * @author Atanu Bhowmick
 *
 */
public class AESSecurityUtil {
	private static final String TOKEN = "passwd";
	private String salt;
	private int pwdIterations = 65536;
	private int keySize = 256;
	private byte[] ivBytes;
	private String keyAlgorithm = "AES";
	private String encryptAlgorithm = "AES/CBC/PKCS5Padding";
	private String secretKeyFactoryAlgorithm = "PBKDF2WithHmacSHA1";

	public AESSecurityUtil() {
		this.salt = getSalt();
	}

	private String getSalt() {
		SecureRandom random = new SecureRandom();
		byte bytes[] = new byte[20];
		random.nextBytes(bytes);
		String text = new String(bytes, StandardCharsets.UTF_8);
		return text;
	}

	/**
	 * 
	 * @param plainText
	 * @return encrypted text
	 * @throws Exception
	 */
	public String encyrpt(String plainText) {
		try {
			// generate key
			byte[] saltBytes = salt.getBytes(StandardCharsets.UTF_8);

			SecretKeyFactory skf = SecretKeyFactory.getInstance(this.secretKeyFactoryAlgorithm);
			PBEKeySpec spec = new PBEKeySpec(TOKEN.toCharArray(), saltBytes, this.pwdIterations, this.keySize);
			SecretKey secretKey = skf.generateSecret(spec);
			SecretKeySpec key = new SecretKeySpec(secretKey.getEncoded(), keyAlgorithm);

			// AES initialization
			Cipher cipher = Cipher.getInstance(encryptAlgorithm);
			cipher.init(Cipher.ENCRYPT_MODE, key);

			// generate IV
			this.ivBytes = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
			byte[] encryptedText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
			return Base64.getEncoder().encodeToString(encryptedText);
		} catch (Exception e) {
			throw new GatewayException("", "", e);
		}
	}

	/**
	 * 
	 * @param encryptText
	 * @return decrypted text
	 * @throws Exception
	 */
	public String decrypt(String encryptText) {
		byte[] saltBytes = salt.getBytes(StandardCharsets.UTF_8);
		byte[] encryptTextBytes = Base64.getDecoder().decode(encryptText);

		try {
			SecretKeyFactory skf = SecretKeyFactory.getInstance(this.secretKeyFactoryAlgorithm);
			PBEKeySpec spec = new PBEKeySpec(TOKEN.toCharArray(), saltBytes, this.pwdIterations, this.keySize);
			SecretKey secretKey = skf.generateSecret(spec);
			SecretKeySpec key = new SecretKeySpec(secretKey.getEncoded(), keyAlgorithm);

			// decrypt the message
			Cipher cipher = Cipher.getInstance(encryptAlgorithm);
			cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivBytes));

			byte[] decyrptTextBytes = null;

			decyrptTextBytes = cipher.doFinal(encryptTextBytes);
			return new String(decyrptTextBytes, StandardCharsets.UTF_8);
		} catch (Exception e) {
			throw new GatewayException("", "", e);
		}
	}
}
