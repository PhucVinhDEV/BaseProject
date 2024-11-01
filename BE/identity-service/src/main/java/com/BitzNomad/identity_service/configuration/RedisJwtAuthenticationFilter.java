package com.BitzNomad.identity_service.configuration;

import com.BitzNomad.identity_service.Exception.AppException;
import com.BitzNomad.identity_service.Exception.ErrorCode;
import com.BitzNomad.identity_service.Service.AuthenticationService;
import com.BitzNomad.identity_service.Service.AuthenticationService2;
import com.BitzNomad.identity_service.Service.RedisService;
import com.BitzNomad.identity_service.entity.Auth.User;
import com.BitzNomad.identity_service.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static org.hibernate.query.sqm.tree.SqmNode.log;

@RequiredArgsConstructor
public class RedisJwtAuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationService2 authenticationService;
    private final UserRepository userRepository;
    private final RedisService redisService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String token = extractTokenFromRequest(request);

        if (token != null) {
            try {
                // Xác thực JWT và lấy thông tin người dùng
                var signedJWT = authenticationService.verifyToken(token, false);
                String userId = signedJWT.getJWTClaimsSet().getSubject();

                // Tìm người dùng bằng email
                User user = userRepository.findByEmail(userId).orElseThrow(
                        () -> new AppException(ErrorCode.USER_NOT_EXISTED)
                );

                // Kiểm tra token trong Redis
                String redisToken = String.valueOf(redisService.getValue(user.getId()));
                if (!redisToken.equals(token)) {
                    throw new AppException(ErrorCode.JWT_AUTHENTICATION_FAILED);
                }

                // Thiết lập thông tin xác thực vào SecurityContext
                Authentication authentication = new UsernamePasswordAuthenticationToken(userId, null, null);
                SecurityContextHolder.getContext().setAuthentication(authentication);

            } catch (AppException e) {
                log.error("JWT Authentication failed: {}"+ e.getMessage());
                throw new AppException(ErrorCode.JWT_AUTHENTICATION_FAILED);
            } catch (Exception e) {
                // Xử lý các lỗi không mong muốn khác
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error: " + e.getMessage());
                return;
            }
        }

        // Tiếp tục chuỗi filter nếu không có lỗi
        filterChain.doFilter(request, response);
    }

    private String extractTokenFromRequest(HttpServletRequest request) {
        // Lấy giá trị header Authorization từ request
        String bearerToken = request.getHeader("Authorization");



        // Kiểm tra xem bearerToken có khác null và có bắt đầu bằng "Bearer " không
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            // Trả về phần token không bao gồm tiền tố "Bearer "
            return bearerToken.substring(7);
        }

        // Nếu không có token, trả về null
        return null;
    }
}
