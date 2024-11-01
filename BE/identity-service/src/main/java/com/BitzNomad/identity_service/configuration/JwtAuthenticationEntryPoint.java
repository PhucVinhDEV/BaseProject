package com.BitzNomad.identity_service.configuration;

import com.BitzNomad.identity_service.DtoReponese.ApiResponse;
import com.BitzNomad.identity_service.Exception.AppException;
import com.BitzNomad.identity_service.Exception.ErrorCode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;

public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        // Mặc định lỗi sẽ là UNAUTHENTICATED
        ErrorCode errorCode = ErrorCode.UNAUTHENTICATED;

        // Kiểm tra xem có ngoại lệ AppException hay không, và nếu có, lấy ErrorCode tương ứng
        if (authException.getCause() instanceof AppException) {
            AppException appException = (AppException) authException.getCause();
            errorCode = appException.getErrorCode();
        }

        // Thiết lập phản hồi HTTP với mã trạng thái và nội dung là JSON
        response.setStatus(errorCode.getHttpStatus().value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        // Tạo ApiResponse để trả về
        ApiResponse<?> apiResponse = ApiResponse.builder()
                .status(errorCode.getCode())
                .message(errorCode.getMessage())
                .build();

        // Chuyển đổi ApiResponse thành JSON và trả về cho client
        ObjectMapper objectMapper = new ObjectMapper();
        response.getWriter().write(objectMapper.writeValueAsString(apiResponse));
        response.flushBuffer();
    }
}
