package com.exemple.auth.repository;

import java.util.Optional;

import com.exemple.auth.models.ERole;
import com.exemple.auth.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}