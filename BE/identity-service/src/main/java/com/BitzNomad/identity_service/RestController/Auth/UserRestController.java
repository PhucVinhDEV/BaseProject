package com.BitzNomad.identity_service.RestController.Auth;

import com.BitzNomad.identity_service.DtoReponese.ApiResponse;
import com.BitzNomad.identity_service.DtoReponese.UserReponese;
import com.BitzNomad.identity_service.DtoRequest.UserCreateRequest;
import com.BitzNomad.identity_service.DtoRequest.UserUpdateRequest;
import com.BitzNomad.identity_service.Mapper.Auth.UserMapper;
import com.BitzNomad.identity_service.Service.UserService;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.validation.Valid;
import lombok.AccessLevel;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;


@RestController
@Slf4j
@RequestMapping("/api/user")
@FieldDefaults(level = AccessLevel.PRIVATE)
@SecurityRequirement(name = "bearer-key")
public class UserRestController {


    @Autowired
    UserService userService;

    @Autowired
    UserMapper userMapper;

    @PostMapping
    ApiResponse<UserReponese> createUser( @RequestBody @Valid UserCreateRequest request) {
        log.info("User created");
        return ApiResponse.<UserReponese>builder()
                .status(HttpStatus.CREATED.value())
                .message("User created")
                .result(userService.createUser(request))
                .build();
    }

    @GetMapping("/myinfo")
    ApiResponse<UserReponese> getMyInfo() {
        return ApiResponse.<UserReponese>builder()
                .message("Your account login is info :")
                .status(200)
                .result(userService.getMyInfo())
                .build();
    }

    @GetMapping("/{id}")
    ResponseEntity<ApiResponse<UserReponese>> getUserById(@PathVariable String id) {
        log.info("Getting user with id: {}", id);
        ApiResponse<UserReponese> result = new ApiResponse<>();
        result.setResult(userMapper.convertUserToReponese(userService.getUserById(id)));
        result.setStatus(200);
        return ResponseEntity.ok(result);
    }

    @PutMapping()
    ApiResponse<UserReponese> updateUser(@RequestBody @Valid  UserUpdateRequest request) {
        log.info("Updating user with id: {}" , request.getUsername());
        return ApiResponse.<UserReponese>builder()
                .message("User"+ request.getUsername()+ "updated successfully")
                .status(200)
                .result(userMapper.convertUserToReponese(userService.updateUser(request)))
                .build();
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    void deleteUser(@PathVariable String id) {
        log.info("Deleting user with id: {}", id);
        userService.deleteUser(id);
    }

    @GetMapping
    ApiResponse<List<UserReponese>> getAllUsers() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();

        log.info("User name: {}", authentication.getName());
        authentication.getAuthorities().forEach(g -> log.info("GrantedAuthority: {}", g));
        return ApiResponse.<List<UserReponese>>builder()
                .status(200)
                .message("All users")
                .result(userService.getAllUsers())
                .build();
    }


}
