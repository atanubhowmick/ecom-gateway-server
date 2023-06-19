/**
 * 
 */
package dev.atanu.ecom.gateway.security;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

import dev.atanu.ecom.gateway.constant.ErrorCode;
import dev.atanu.ecom.gateway.exception.GatewayException;

/**
 * A class to perform RSA encryption and decryption <br>
 * {@link https://niels.nu/blog/2016/java-rsa.html}
 * 
 * @author Atanu Bhowmick
 *
 */
public class RSASecurityUtil {

	private RSASecurityUtil() {
		// Private Constructor
	}

	/**
	 * 
	 * @return {@link SecurityKeyDetails}
	 */
	public static SecurityKeyDetails generateKeys() {
		KeyPair keyPair = generateKeyPair();
		byte[] publicKeybyte = keyPair.getPublic().getEncoded();
		byte[] privateKeybyte = keyPair.getPrivate().getEncoded();

		SecurityKeyDetails keyDetails = new SecurityKeyDetails();
		keyDetails.setPublicKeyString(Base64.getEncoder().encodeToString(publicKeybyte));
		keyDetails.setPrivateKeyString(Base64.getEncoder().encodeToString(privateKeybyte));

		return keyDetails;
	}

	/**
	 * Generate Public & Private Key Pair
	 * 
	 * @return {@link KeyPair}
	 */
	private static KeyPair generateKeyPair() {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance(SecurityConstant.ENCRYPTION_RSA);
			generator.initialize(SecurityConstant.RSA_KEY_LENGTH, new SecureRandom());
			return generator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			throw new GatewayException(ErrorCode.GATEWAY_S001.name(), ErrorCode.GATEWAY_S001.getErrorMsg(), e);
		}
	}

	/**
	 * Encrypt using public key string
	 * 
	 * @param plainText
	 * @param publicKey
	 * @return Cipher Text
	 */
	public static String encrypt(String plainText, String publicKey) {
		return encrypt(plainText, getPublicKey(publicKey));
	}

	/**
	 * Encrypt Plain Text
	 * 
	 * @param plainText
	 * @param publicKey
	 * @return Encrypted String
	 */
	public static String encrypt(String plainText, PublicKey publicKey) {
		try {
			Cipher encryptCipher = Cipher.getInstance(SecurityConstant.RSA_ENCRYPT_ALGORITHM);
			encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
			byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
			return Base64.getEncoder().encodeToString(cipherText);
		} catch (Exception e) {
			throw new GatewayException(ErrorCode.GATEWAY_S002.name(), ErrorCode.GATEWAY_S002.getErrorMsg(), e);
		}
	}

	public static String decrypt(String cipherText, String privateKey) {
		try {
			return decrypt(cipherText, getPrivateKey(privateKey));
		} catch (Exception e) {
			throw new GatewayException(ErrorCode.GATEWAY_S003.name(), ErrorCode.GATEWAY_S003.getErrorMsg(), e);
		}
	}

	/**
	 * Decrypt the encrypted text
	 * 
	 * @param cipherText
	 * @param privateKey
	 * @return Decrypted String
	 */
	public static String decrypt(String cipherText, PrivateKey privateKey) {
		try {
			byte[] bytes = Base64.getDecoder().decode(cipherText);
			Cipher decriptCipher = Cipher.getInstance(SecurityConstant.RSA_ENCRYPT_ALGORITHM);
			decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);
			return new String(decriptCipher.doFinal(bytes), StandardCharsets.UTF_8);
		} catch (Exception e) {
			throw new GatewayException(ErrorCode.GATEWAY_S003.name(), ErrorCode.GATEWAY_S003.getErrorMsg(), e);
		}
	}

	/**
	 * Sign using private key string
	 * 
	 * @param plainText
	 * @param privateKey
	 * @return signature
	 */
	public static String sign(String plainText, String privateKey) {
		return sign(plainText, getPrivateKey(privateKey));
	}

	/**
	 * Sign with Private Key
	 * 
	 * @param plainText
	 * @param privateKey
	 * @return Signed String
	 */
	private static String sign(String plainText, PrivateKey privateKey) {
		try {
			Signature privateSignature = Signature.getInstance(SecurityConstant.RSA_SIGNATURE_SHA);
			privateSignature.initSign(privateKey);
			privateSignature.update(plainText.getBytes(StandardCharsets.UTF_8));
			byte[] signature = privateSignature.sign();
			return Base64.getEncoder().encodeToString(signature);
		} catch (Exception e) {
			throw new GatewayException(ErrorCode.GATEWAY_S003.name(), ErrorCode.GATEWAY_S003.getErrorMsg(), e);
		}
	}

	/**
	 * Verify Signature with Public Key
	 * 
	 * @param plainText
	 * @param signature
	 * @param publicKey
	 * @return boolean - verifiedSign
	 */
	public static boolean verify(String plainText, String signature, String publicKey) {
		return verify(plainText, signature, getPublicKey(publicKey));
	}

	/**
	 * Verify Signature with Public Key
	 * 
	 * @param plainText
	 * @param signature
	 * @param publicKey
	 * @return boolean - verifiedSign
	 */
	private static boolean verify(String plainText, String signature, PublicKey publicKey) {
		try {
			Signature publicSignature = Signature.getInstance(SecurityConstant.RSA_SIGNATURE_SHA);
			publicSignature.initVerify(publicKey);
			publicSignature.update(plainText.getBytes(StandardCharsets.UTF_8));
			byte[] signatureBytes = Base64.getDecoder().decode(signature);
			return publicSignature.verify(signatureBytes);
		} catch (Exception e) {
			throw new GatewayException(ErrorCode.GATEWAY_S004.name(), ErrorCode.GATEWAY_S004.getErrorMsg(), e);
		}
	}

	/**
	 * Get PublicKey from String
	 * 
	 * @param publicKey
	 * @return PublicKey
	 */
	private static PublicKey getPublicKey(String publicKey) {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance(SecurityConstant.ENCRYPTION_RSA);
			return keyFactory.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey)));
		} catch (Exception e) {
			throw new GatewayException(ErrorCode.GATEWAY_S001.name(), ErrorCode.GATEWAY_S001.getErrorMsg(), e);
		}
	}

	/**
	 * Get PrivateKey from String
	 * 
	 * @param privateKey
	 * @return PrivateKey
	 */
	private static PrivateKey getPrivateKey(String privateKey) {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance(SecurityConstant.ENCRYPTION_RSA);
			return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey)));
		} catch (Exception e) {
			throw new GatewayException(ErrorCode.GATEWAY_S001.name(), ErrorCode.GATEWAY_S001.getErrorMsg(), e);
		}
	}
}
