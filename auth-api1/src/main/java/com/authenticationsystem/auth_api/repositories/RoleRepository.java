package com.authenticationsystem.auth_api.repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.authenticationsystem.auth_api.models.ERole;
import com.authenticationsystem.auth_api.models.Role;

public interface RoleRepository extends JpaRepository<Role, Long>{

	
	Optional<Role> findByName(ERole name);
}
