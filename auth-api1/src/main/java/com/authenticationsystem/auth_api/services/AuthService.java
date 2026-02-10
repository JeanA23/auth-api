package com.authenticationsystem.auth_api.services;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.authenticationsystem.auth_api.dto.LoginRequest;
import com.authenticationsystem.auth_api.dto.LoginResponse;
import com.authenticationsystem.auth_api.dto.RegisterRequest;
import com.authenticationsystem.auth_api.dto.RegisterUserResponse;
import com.authenticationsystem.auth_api.dto.UserResponse;
import com.authenticationsystem.auth_api.models.ERole;
import com.authenticationsystem.auth_api.models.Role;
import com.authenticationsystem.auth_api.models.User;
import com.authenticationsystem.auth_api.repositories.RoleRepository;
import com.authenticationsystem.auth_api.repositories.UserRepository;
import com.authenticationsystem.auth_api.security.UserDetailsImpl;
import com.authenticationsystem.auth_api.securityJwt.JwtUtils;
import com.authenticationsystem.auth_api.utils.Response;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final JwtUtils jwtUtils;

    private final AuthenticationManager authenticationManager;

    private final PasswordEncoder passwordEncoder;

    private final RoleRepository roleRepository;

    private final UserRepository userRepository;


	//Register Function
	
	@Transactional
	public Response<Object> register(RegisterRequest request) {
		
		if(userRepository.existsByUsername(request.getUsername())) {
			
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username already registered");
		}
		
		if(userRepository.existsByEmail(request.getEmail())) {
			
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email already registered");
		}
		
		// generate bcrypt password
		String hashedPassword = passwordEncoder.encode(request.getPassword());
		
		//Define User instance, then new value
		User user = new User();
		
		user.setUsername(request.getUsername());
		user.setEmail(request.getEmail());
		user.setPassword(hashedPassword);
		user.setIsActive(true);
		
		//Set default role to ROLE_ADMIN
		
		Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
				.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
		
		Set<Role> roles = new HashSet<>();
		roles.add(adminRole);
		user.setRoles(roles);
		
		//save user
		userRepository.save(user);
		
		//return response DTO
		RegisterUserResponse registerUserResponse = RegisterUserResponse.builder()
				.name(user.getUsername())
				.email(user.getEmail())
				.build();
		
		return Response.builder()
				.responseCode(200)
				.responseMessage("SUCCESS")
				.data(registerUserResponse)
				.build();
	}
	
	// Login Function
	@Transactional
	public Response<Object> login(LoginRequest request, HttpServletResponse response){
		
		//check if User by Email exist. if not throw error
		userRepository.findFirstByEmail(request.getEmail())
		.orElseThrow(() -> new RuntimeException("User not found. Please register first"));
		
		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
		
		SecurityContextHolder.getContext().setAuthentication(authentication);
		
		UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
		
		String jwt = jwtUtils.generateJwtToken(userDetails);
		
		List<String> roles = userDetails.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority)
				.toList();
		
		LoginResponse loginResponse = LoginResponse.builder()
				.username(userDetails.getUsername())
				.email(userDetails.getEmail())
				.roles(roles)
				.accessToken(jwt)
				.tokenType("Bearer")
				.build();
		
		return Response.builder()
				.responseCode(200)
				.responseMessage("SUCCESS")
				.data(loginResponse)
				.build();
	}
	
	// Get User that currently login
	@Transactional
	public Response<Object> getUser(){
		
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		
		UserDetailsImpl userDetailsImpl = (UserDetailsImpl) authentication.getPrincipal();
		
		Long userId = userDetailsImpl.getId();
		
		User user = userRepository.findById(userId)
				.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Email not found !"));
		
		UserResponse userResponse = UserResponse.builder()
				.id(user.getId())
				.username(user.getUsername())
				.email(user.getEmail())
				.isActive(user.getIsActive())
				.roles(user.getRoles().stream().map(Role::getName).toList())
				.build();
		
		return Response.builder()
				.responseCode(200)
				.responseMessage("SUCCESS")
				.data(userResponse)
				.build();
	}
}
