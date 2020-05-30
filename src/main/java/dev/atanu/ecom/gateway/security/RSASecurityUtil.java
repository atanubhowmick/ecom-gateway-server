/**
 * 
 */
package dev.atanu.ecom.gateway.security;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import dev.atanu.ecom.gateway.constant.ErrorCode;
import dev.atanu.ecom.gateway.exception.GatewayException;

/**
 * Class for RSA Security <br>
 * {@link https://niels.nu/blog/2016/java-rsa.html}
 * 
 * @author Atanu Bhowmick
 *
 */
public class RSASecurityUtil {

	private RSASecurityUtil() {
		// Private Constructor
	}

	public static void main(String[] args) {
		SecurityKeyDetails details = generateKeys();
		System.out.println(details);
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
		keyDetails.setPublicKey(keyPair.getPublic());
		keyDetails.setPrivateKey(keyPair.getPrivate());
		keyDetails.setAlgorithm(SecurityConstant.ENCRYPTION_ALGORITHM_RSA);
		keyDetails.setKeySize(SecurityConstant.ENCRYPTION_LENGTH);
		keyDetails.setPublicKeyString(Base64.getEncoder().encodeToString(publicKeybyte));
		keyDetails.setPrivateKeyString(Base64.getEncoder().encodeToString(privateKeybyte));
		String randomString = RandomStringGenerator.getRandomString(SecurityConstant.OFFSET_LENGTH);
		keyDetails.setSignature(sign(randomString, keyPair.getPrivate()));
		keyDetails.setOffset(RandomStringGenerator.getRandomString(64));

		return keyDetails;
	}

	/**
	 * Generate Public & Private Key Pair
	 * 
	 * @return {@link KeyPair}
	 */
	private static KeyPair generateKeyPair() {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance(SecurityConstant.ENCRYPTION_ALGORITHM_RSA);
			generator.initialize(SecurityConstant.ENCRYPTION_LENGTH, new SecureRandom());
			return generator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			throw new GatewayException(ErrorCode.GATEWAY_S001.name(), ErrorCode.GATEWAY_S001.getErrorMsg(), e);
		}
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
			Cipher encryptCipher = Cipher.getInstance(SecurityConstant.ENCRYPTION_PADDING_RSA);
			encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
			byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
			return Base64.getEncoder().encodeToString(cipherText);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException e) {
			throw new GatewayException(ErrorCode.GATEWAY_S002.name(), ErrorCode.GATEWAY_S002.getErrorMsg(), e);
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
			Cipher decriptCipher = Cipher.getInstance(SecurityConstant.DECRYPTION_PADDING_RSA);
			decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);
			return new String(decriptCipher.doFinal(bytes), StandardCharsets.UTF_8);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException e) {
			throw new GatewayException(ErrorCode.GATEWAY_S003.name(), ErrorCode.GATEWAY_S003.getErrorMsg(), e);
		}
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
			Signature privateSignature = Signature.getInstance(SecurityConstant.SIGNATURE_RSA_SHA);
			privateSignature.initSign(privateKey);
			privateSignature.update(plainText.getBytes(StandardCharsets.UTF_8));
			byte[] signature = privateSignature.sign();
			return Base64.getEncoder().encodeToString(signature);
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			throw new GatewayException(ErrorCode.GATEWAY_S003.name(), ErrorCode.GATEWAY_S003.getErrorMsg(), e);
		}
	}

	/**
	 * Verify Sign with Public Key
	 * 
	 * @param plainText
	 * @param signature
	 * @param publicKey
	 * @return boolean - verifiedSign
	 */
	public static boolean verify(String plainText, String signature, PublicKey publicKey) {
		try {
			Signature publicSignature = Signature.getInstance(SecurityConstant.SIGNATURE_RSA_SHA);
			publicSignature.initVerify(publicKey);
			publicSignature.update(plainText.getBytes(StandardCharsets.UTF_8));
			byte[] signatureBytes = Base64.getDecoder().decode(signature);
			return publicSignature.verify(signatureBytes);
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			throw new GatewayException(ErrorCode.GATEWAY_S004.name(), ErrorCode.GATEWAY_S004.getErrorMsg(), e);
		}
	}
}
