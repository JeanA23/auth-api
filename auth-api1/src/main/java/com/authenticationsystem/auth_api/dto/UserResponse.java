package com.authenticationsystem.auth_api.dto;

import java.util.List;

import com.authenticationsystem.auth_api.models.ERole;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserResponse {

	private Long id;
    private String username;
    private String email;

    @JsonProperty("is_activeR")
    private Boolean isActive;

    private List<ERole> roles;
}
