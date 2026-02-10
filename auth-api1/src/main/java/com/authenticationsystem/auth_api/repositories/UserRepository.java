package com.authenticationsystem.auth_api.repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.authenticationsystem.auth_api.models.User;

public interface UserRepository extends JpaRepository<User, Long>{
	
	Optional<User> findByUsername(String username);
	
	Optional<User> findFirstByEmail(String email);
	
	Boolean existsByEmail(String email);
	
	Boolean existsByUsername(String username);

}
