/**
 * 
 */
package dev.atanu.ecom.gateway.dto;

import java.io.Serializable;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Ignore unknown properties
 * <br>
 * https://stackoverflow.com/questions/5455014/ignoring-new-fields-on-json-objects-using-jackson
 * 
 * @author Atanu Bhowmick
 *
 */
@JsonInclude(value = Include.ALWAYS)
@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class AbstractBaseDTO implements Serializable {

	private static final long serialVersionUID = 5274512655216948657L;

	/**
	 * Overriding toString method to return JSON String 
	 * <br>
	 * https://stackoverflow.com/questions/16527932/ok-to-use-json-output-as-default
	 * -for-tostring
	 */
	@Override
	public String toString() {
		String objectString = null;
		try {
			objectString = new ObjectMapper().writeValueAsString(this);
		} catch (JsonProcessingException e) {
			objectString = super.toString();
		}
		return objectString;
	}
}
