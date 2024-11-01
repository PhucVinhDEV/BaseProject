package com.BitzNomad.identity_service.configuration;

import com.BitzNomad.identity_service.constant.PredefinePermission;
import com.BitzNomad.identity_service.constant.PredefineRole;
import com.BitzNomad.identity_service.entity.Auth.Permission;
import com.BitzNomad.identity_service.entity.Auth.Role;
import com.BitzNomad.identity_service.entity.Auth.User;
import com.BitzNomad.identity_service.repository.PermissionRepository;
import com.BitzNomad.identity_service.repository.RoleRepository;
import com.BitzNomad.identity_service.repository.UserRepository;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import lombok.AccessLevel;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;


import java.util.HashSet;
import java.util.Set;

@Configuration
@FieldDefaults(level = AccessLevel.PRIVATE)
@Slf4j
public class ApplicationConfig {
    @NonFinal
    static final String ADMIN_USER_NAME = "admin";

    @NonFinal
    static final String ADMIN_PASSWORD = "admin";


    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PermissionRepository permissionRepository;


    @Bean
    ApplicationRunner applicationRunner(PasswordEncoder passwordEncoder) {
        return args -> {
            // Tạo các quyền CRUD
            createPermissionIfNotExists(PredefinePermission.CREATE_PERMISSION, "Create permission");
            createPermissionIfNotExists(PredefinePermission.UPDATE_PERMISSION, "Update permission");
            createPermissionIfNotExists(PredefinePermission.DELETE_PERMISSION, "Delete permission");
            createPermissionIfNotExists(PredefinePermission.VIEW_PERMISSION, "Read permission");

            createPermissionIfNotExists(PredefinePermission.VIEW_ROLE,"Read role");
            createPermissionIfNotExists(PredefinePermission.CREATOR_ROLE, "Create role");
            createPermissionIfNotExists(PredefinePermission.UPDATE_ROLE,"Update role");
            createPermissionIfNotExists(PredefinePermission.DELETE_ROLE,"Delete role");
// Tạo role với các quyền CRUD

            Role adminRole = roleRepository.save(Role.builder()
                    .name(PredefineRole.ADMIN_ROLE)
                    .description("Admin role")
                    .permissions(
                            new HashSet<>(permissionRepository.findAll())
                    )
                    .build());

            Role userRole = roleRepository.save(Role.builder()
                    .name(PredefineRole.USER_ROLE)
                    .description("User role")
                    .permissions(Set.of(
                    ))
                    .build());

            Role customerRole = roleRepository.save(Role.builder()
                    .name(PredefineRole.OWNER_ROLE)
                    .description("Customer role")
                    .permissions(Set.of(
                    ))
                    .build());

            // Tạo user với role admin
            if (userRepository.findByEmail("admin").isEmpty()) {
                Set<Role> roles = new HashSet<>();
                roles.add(adminRole);

                User user = User.builder()
                        .email(ADMIN_USER_NAME)
                        .password(passwordEncoder.encode(ADMIN_PASSWORD))
                        .roles(roles)
                        .build();
                userRepository.save(user);

                log.warn("admin user has been created with default password: admin, please change it");
            }
        };
    }
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);
    }

    @Bean
    ModelMapper modelMapper() {
        return new ModelMapper();
    }



    // Phương thức tạo quyền nếu chưa tồn tại
    private void createPermissionIfNotExists(String name, String description) {
        if (!permissionRepository.existsById(name)) {
            permissionRepository.save(Permission.builder()
                    .name(name)
                    .description(description)
                    .build());
        }
    }
    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .addSecurityItem(new SecurityRequirement().addList("bearer-key"))
                .components(new Components()
                        .addSecuritySchemes("bearer-key", new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")));
    }


}
