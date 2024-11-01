package com.BitzNomad.identity_service.entity.Auth;

import com.BitzNomad.identity_service.entity.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.time.LocalDate;
import java.util.Set;

@Entity
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class User extends BaseEntity<String> {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    String id;


    String email;


    String password;


    String firstName;


    String lastName;

  // date of birth
    LocalDate dob;

    @ManyToMany
    Set<Role> roles;
}
