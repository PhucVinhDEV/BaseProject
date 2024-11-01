package com.BitzNomad.identity_service.Service;

import com.BitzNomad.identity_service.DtoReponese.AuthenticationResponse;
import com.BitzNomad.identity_service.DtoReponese.IntrospecResponsee;
import com.BitzNomad.identity_service.DtoRequest.*;
import com.BitzNomad.identity_service.Exception.AppException;
import com.BitzNomad.identity_service.Exception.ErrorCode;
import com.BitzNomad.identity_service.Utils.RandomPasswordGenerator;
import com.BitzNomad.identity_service.constant.PredefineRole;
import com.BitzNomad.identity_service.entity.Auth.Role;
import com.BitzNomad.identity_service.entity.Auth.User;
import com.BitzNomad.identity_service.entity.InvalidatedToken;
import com.BitzNomad.identity_service.repository.InvalidatedRepository;
import com.BitzNomad.identity_service.repository.UserRepository;
import com.BitzNomad.identity_service.repository.httpclient.OutboundIdentityClient;
import com.BitzNomad.identity_service.repository.httpclient.OutboundUserClient;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.experimental.NonFinal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationService2 {
    @Autowired
    UserRepository userRepository;

    @Autowired
    InvalidatedRepository invalidatedTokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private RedisService redisService;

    @Value("${jwt.secretKey}")
    private String SignerKey;

    @Value("${jwt.valid-duration}")
    protected long VALID_DURATION;

    @Value("${jwt.refreshable-duration}")
    protected long REFRESHABLE_DURATION;

    // Authenticate user and store JWT in Redis
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        var user = userRepository.findByEmail(request.getUsername())
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        boolean authenticated = passwordEncoder.matches(request.getPassword(), user.getPassword());
        if (!authenticated) {
            throw new AppException(ErrorCode.UNAUTHENTICATED);
        }

        // Generate JWT token
        String token = generateToken(user);

        // Store JWT in Redis with expiration (TTL)
        redisService.setValueWithTTL(user.getId(), token, VALID_DURATION, TimeUnit.SECONDS);

        return AuthenticationResponse.builder()
                .token(token)
                .authenticated(true)
                .build();
    }

    // Generate JWT token
    public String generateToken(User user) {
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS512);
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject(user.getEmail())
                .issuer("BitzNomad.com")
                .issueTime(new Date())
                .expirationTime(new Date(Instant.now().plus(VALID_DURATION, ChronoUnit.SECONDS).toEpochMilli()))
                .jwtID(UUID.randomUUID().toString())
                .claim("scope", buildScope(user))
                .build();

        JWSObject jwsObject = new JWSObject(header, new Payload(jwtClaimsSet.toJSONObject()));

        try {
            jwsObject.sign(new MACSigner(SignerKey.getBytes()));
            return jwsObject.serialize();
        } catch (JOSEException e) {
            log.error("JWT Signing Exception", e);
            throw new RuntimeException(e);
        }
    }

    // Refresh token and invalidate the old one in Redis
    public AuthenticationResponse refreshToken(RefeshRequest request) throws ParseException, JOSEException {
        SignedJWT signedJWT = verifyToken(request.getToken(), true);

        String jwtId = signedJWT.getJWTClaimsSet().getJWTID();
        var expirationTime = signedJWT.getJWTClaimsSet().getExpirationTime();
        invalidatedTokenRepository.save(InvalidatedToken.builder().id(jwtId).expiryTime(expirationTime).build());

        String email = signedJWT.getJWTClaimsSet().getSubject();
        var user = userRepository.findByEmail(email).orElseThrow(() -> new AppException(ErrorCode.UNAUTHORIZED));

        // Generate new token and store in Redis
        String newToken = generateToken(user);
        redisService.setValueWithTTL(user.getId(), newToken, VALID_DURATION, TimeUnit.SECONDS);

        return AuthenticationResponse.builder()
                .token(newToken)
                .authenticated(true)
                .build();
    }

    // Logout user by invalidating the token
    public void logout(LogoutRequest request) throws ParseException, JOSEException {
        SignedJWT signedJWT = verifyToken(request.getToken(), false);
        String userId = signedJWT.getJWTClaimsSet().getSubject();

        // Remove token from Redis
        redisService.deleteValue(userId);
    }

    // Introspection to check if token is valid
    public IntrospecResponsee introspect(IntrospecRequest request) throws JOSEException, ParseException {
        boolean isValid = true;
        try {
            verifyToken(request.getToken(), false);
        } catch (AppException exception) {
            isValid = false;
        }
        return IntrospecResponsee.builder()
                .valid(isValid)
                .build();
    }

    // Verify JWT token and check Redis for validity
    public SignedJWT verifyToken(String token, boolean isRefresh) throws ParseException, JOSEException {
        JWSVerifier verifier = new MACVerifier(SignerKey.getBytes());
        SignedJWT signedJWT = SignedJWT.parse(token);

        String userId = signedJWT.getJWTClaimsSet().getSubject();
        User user = userRepository.findByEmail(userId)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        // Kiểm tra token có tồn tại trong Redis không
        String redisToken = (String) redisService.getValue(user.getId());
        if (redisToken == null) {
            log.error("Token không tồn tại trong Redis cho user ID: {}", user.getId());
            throw new AppException(ErrorCode.UNAUTHENTICATED);
        } else if (!redisToken.equals(token)) {
            log.error("Token không khớp. Redis token: {}, JWT token: {}", redisToken, token);
            throw new AppException(ErrorCode.JWT_AUTHENTICATION_FAILED);
        }

        // Kiểm tra thời hạn của token
        Date expirationTime = isRefresh
                ? new Date(signedJWT.getJWTClaimsSet().getIssueTime().toInstant().plus(REFRESHABLE_DURATION, ChronoUnit.SECONDS).toEpochMilli())
                : signedJWT.getJWTClaimsSet().getExpirationTime();

        boolean verified = signedJWT.verify(verifier);
        if (!verified) {
            log.error("Token signature verification failed for user ID: {}", user.getId());
            throw new AppException(ErrorCode.JWT_AUTHENTICATION_FAILED);
        }

        if (expirationTime.before(new Date())) {
            log.error("Token đã hết hạn cho user ID: {}", user.getId());
            throw new AppException(ErrorCode.UNAUTHENTICATED);
        }

        // Kiểm tra xem token có bị vô hiệu hóa không
        if (invalidatedTokenRepository.existsById(signedJWT.getJWTClaimsSet().getJWTID())) {
            log.error("Token đã bị vô hiệu hóa cho user ID: {}", user.getId());
            throw new AppException(ErrorCode.UNAUTHENTICATED);
        }

        return signedJWT;
    }

    private String buildScope(User user) {
        StringBuilder scopeBuilder = new StringBuilder();
        Set<Role> roles = user.getRoles();
        if (!CollectionUtils.isEmpty(roles)) {
            roles.forEach(role -> {
                scopeBuilder.append("ROLE_").append(role.getName()).append(" ");
            });
        }
        return scopeBuilder.toString().trim();
    }
}
