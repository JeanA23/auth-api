package com.authenticationsystem.auth_api.web;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.authenticationsystem.auth_api.dto.LoginRequest;
import com.authenticationsystem.auth_api.dto.RegisterRequest;
import com.authenticationsystem.auth_api.services.AuthService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

	private final AuthService authService;
	
	// REGISTER
    @PostMapping(path = "/register")
    public ResponseEntity<Object> register(@Valid @RequestBody RegisterRequest request) {
    	
        return ResponseEntity.ok(authService.register(request));
    }

    // LOGIN
    @PostMapping("/login")
    public ResponseEntity<Object> login(@Valid @RequestBody LoginRequest request) {
    	
        return ResponseEntity.ok(authService.login(request, null));
    }

    // GET USER THAT CURRENTLY LOGIN WITH CERTAIN ROLE
    @GetMapping("/user")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<Object> getUser() {
    	
        return ResponseEntity.ok(authService.getUser());
    }
    
    
}
