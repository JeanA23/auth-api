package com.authenticationsystem.auth_api.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.authenticationsystem.auth_api.securityJwt.AuthEntryPointJwt;
import com.authenticationsystem.auth_api.securityJwt.AuthTokenFilter;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class WebSecurityConfig {

	private final UserDetailsServiceImpl userDetailsService;
	private final AuthEntryPointJwt unauthorizedHandler;

	@Bean
	AuthTokenFilter authenticationJwtTokenFilter() {

		return new AuthTokenFilter(null, userDetailsService);
	}


	@Bean
	AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
		
		return authConfig.getAuthenticationManager();
	}

	

	@Bean
	SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

		http.csrf(csrf -> csrf.disable())
				.exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler))
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.authorizeHttpRequests(
						auth -> auth.requestMatchers("/api/v1/auth/**").permitAll().anyRequest().authenticated());

		
		http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);

		return http.build();
	}

}
