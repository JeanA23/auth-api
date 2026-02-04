package com.authenticationsystem.auth_api.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class RegisterUserResponse {

	@NotBlank
	@Size(max = 100)
	private String name;

	@NotBlank
	@Size(max = 100)
	@Email()
	private String email;
}
