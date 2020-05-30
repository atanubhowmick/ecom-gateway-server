/**
 * 
 */
package dev.atanu.ecom.gateway.security;

import java.security.PrivateKey;
import java.security.PublicKey;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * @author Atanu Bhowmick
 *
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class SecurityKeyDetails {

	private String algorithm;
	private int keySize;
	private String offset;
	private String signature;
	private PublicKey publicKey;
	private PrivateKey privateKey;
	private String publicKeyString;
	private String privateKeyString;

	@Override
	public String toString() {
		return "Can't log security details because it contains sensitive information";
	}
}
