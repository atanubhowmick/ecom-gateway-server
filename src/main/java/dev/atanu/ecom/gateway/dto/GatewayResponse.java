/**
 * 
 */
package dev.atanu.ecom.gateway.dto;

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
public class GatewayResponse extends AbstractBaseDTO {

	private static final long serialVersionUID = -1848648610093950624L;

	private String offset;
	private String encPayload;
}
