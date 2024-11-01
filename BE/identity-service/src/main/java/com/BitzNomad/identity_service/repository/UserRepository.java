package com.BitzNomad.identity_service.repository;

import com.BitzNomad.identity_service.entity.Auth.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;


public interface UserRepository extends JpaRepository<User, String> {

    boolean existsByEmail(String email);



    Optional<User> findByEmail(String email);


}
