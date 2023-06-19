/**
 * 
 */
package dev.atanu.ecom.gateway.security;

import dev.atanu.ecom.gateway.dto.AbstractBaseDTO;
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
public class SecurityKeyDetails extends AbstractBaseDTO {

	private static final long serialVersionUID = 3500935564698587875L;

	private String offset;
	private String signature;
	private String publicKeyString;
	private String privateKeyString;

	@Override
	public String toString() {
		return "Can't log security details because it contains sensitive information";
	}
}
