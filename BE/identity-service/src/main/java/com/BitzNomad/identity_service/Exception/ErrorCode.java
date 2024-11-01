package com.BitzNomad.identity_service.Exception;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpStatus;

@Getter
@AllArgsConstructor
public enum ErrorCode {
    UNCATEGORIZED_EXCEPTION(9999,"Uncategorized Exception",HttpStatus.INTERNAL_SERVER_ERROR),
    INVALID_KEY(1001,"Uncategorized Error",HttpStatus.BAD_REQUEST),
    UserExitsted(1002,"UserExitsted",HttpStatus.BAD_REQUEST),
    USER_INVALID(1003,"User must be at least 3 characters long",HttpStatus.BAD_REQUEST),
    PASSWORD_INVALID(1004,"Password must be at least 3 characters long",HttpStatus.BAD_REQUEST),
    USER_NOT_EXISTED(1005,"User not existed",HttpStatus.NOT_FOUND),
    UNAUTHENTICATED(1006,"Unauthenticated",HttpStatus.UNAUTHORIZED),
    UNAUTHORIZED(1007, "You do not have permission", HttpStatus.FORBIDDEN),
    INVALID_DOB(1008, "Your age must be at least {min}", HttpStatus.BAD_REQUEST),
    INVALID_DUONG(1009, "Your name must be at least {name}", HttpStatus.BAD_REQUEST),
    JWT_AUTHENTICATION_FAILED(1010, "JWT authentication failed", HttpStatus.UNAUTHORIZED),
    ;
    private int code;
    private String message;
    private HttpStatus httpStatus;

}
