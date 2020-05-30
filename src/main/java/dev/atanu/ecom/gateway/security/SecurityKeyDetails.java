/**
 * 
 */
package dev.atanu.ecom.gateway.security;

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
	private int length;
	private String publicKey;
	private String privateKey;

	@Override
	public String toString() {
		return "Can't log security details because it contains sensitive information";
	}
}
