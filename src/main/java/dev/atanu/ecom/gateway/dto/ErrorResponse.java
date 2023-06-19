/**
 * 
 */
package dev.atanu.ecom.gateway.dto;

import org.springframework.http.HttpStatus;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
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
@ApiModel(value = "ErrorResponse", description = "Error Details")
public class ErrorResponse extends AbstractBaseDTO {

	private static final long serialVersionUID = 5258511887397146746L;

	@ApiModelProperty(value = "Error Code", example = "CART_E500")
	private String errorCode;

	@ApiModelProperty(value = "Error Message", example = "Internal Server Error. Please try again later!")
	private String errorMessage;

	@ApiModelProperty(value = "Http Status", example = "SUCCESS")
	private HttpStatus httpStatus;

	@ApiModelProperty(value = "HTTP Status code", example = "200")
	private int httpStatusCode;

	/**
	 * Constructor
	 * 
	 * @param errorCode
	 * @param errorMessage
	 * @param httpStatus
	 */
	public ErrorResponse(String errorCode, String errorMessage, HttpStatus httpStatus) {
		this.errorCode = errorCode;
		this.errorMessage = errorMessage;
		this.httpStatus = httpStatus;
		this.httpStatusCode = httpStatus.value();
	}

}
