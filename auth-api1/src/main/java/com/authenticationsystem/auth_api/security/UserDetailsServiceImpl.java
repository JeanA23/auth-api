package com.authenticationsystem.auth_api.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory ;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService ;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import com.authenticationsystem.auth_api.models.User;
import com.authenticationsystem.auth_api.repositories.UserRepository;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

	
	private final UserRepository userRepository;

	@Override
	@Transactional
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		
		User user = userRepository.findByEmail(email).orElseThrow(
				() -> new UsernameNotFoundException("Adresse e-mail de l'utilisateur introuvable : " + email));
		
		//System.out.println(user);
		//logger.info("User trouvé : {}", user.getEmail());
		
		return UserDetailsImpl.build(user);
	}
}
