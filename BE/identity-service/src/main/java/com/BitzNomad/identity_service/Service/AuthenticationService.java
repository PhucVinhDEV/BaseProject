package com.BitzNomad.identity_service.Service;

import com.BitzNomad.identity_service.DtoReponese.AuthenticationResponse;
import com.BitzNomad.identity_service.DtoReponese.IntrospecResponsee;
import com.BitzNomad.identity_service.DtoRequest.*;
import com.BitzNomad.identity_service.Exception.AppException;
import com.BitzNomad.identity_service.Exception.ErrorCode;
import com.BitzNomad.identity_service.Utils.RandomPasswordGenerator;
import com.BitzNomad.identity_service.constant.PredefineRole;
import com.BitzNomad.identity_service.entity.InvalidatedToken;
import com.BitzNomad.identity_service.entity.Auth.Role;
import com.BitzNomad.identity_service.entity.Auth.User;
import com.BitzNomad.identity_service.repository.InvalidatedRepository;
import com.BitzNomad.identity_service.repository.httpclient.OutboundIdentityClient;
import com.BitzNomad.identity_service.repository.UserRepository;
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

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationService {


    @Autowired
    UserRepository userRepository;

    @Autowired
    InvalidatedRepository invalidatedTokenRepository;

    @Autowired
    OutboundIdentityClient outboundIdentityClient;

    @Autowired
    OutboundUserClient  outboundUserClient;

    @Value("${jwt.secretKey}")
    private String SignerKey;

    @NonFinal
    @Value("${jwt.valid-duration}")
    protected long VALID_DURATION;

    @NonFinal
    @Value("${jwt.refreshable-duration}")
    protected long REFRESHABLE_DURATION;

    @NonFinal
    @Value("${outbound.identity.client-id}")
    protected String OUTBOUND_IDENTITY_CLIENT_ID;

    @NonFinal
    @Value("${outbound.identity.redirect-uri}")
    protected String OUTBOUND_IDENTITY_REDIRECT_URI;

    @NonFinal
    @Value("${outbound.identity.client-secret}")
    protected String OUTBOUND_IDENTITY_CLIENT_SECRET;

    @NonFinal
    protected final String GRANT_TYPE = "authorization_code";

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private RedisService redisService;

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        var user = userRepository.findByEmail(request.getUsername()).orElseThrow(() -> new AppException(ErrorCode.UserExitsted));
        boolean authenticated = passwordEncoder.matches(request.getPassword(), user.getPassword());
        if (!authenticated) {
            throw new AppException(ErrorCode.USER_NOT_EXISTED);
        }

        String token = generateToken(user);
        redisService.setValue(user.getId(), token);

        log.info(redisService.getValue(user.getId()).toString());
        return  AuthenticationResponse.builder()
                .token(token)
                .authenticated(authenticated)
                .build();
    }

    public String generateToken(User user) {

        JWSHeader header = new JWSHeader(JWSAlgorithm.HS512);

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject(user.getEmail())
                .issuer("BitzNomad.com")
                .issueTime(new Date())
                .expirationTime(new Date(
                        Instant.now().plus(VALID_DURATION, ChronoUnit.SECONDS).toEpochMilli()
                ))
                .jwtID(UUID.randomUUID().toString())
                .claim("scope",buildScope(user))
                .build();
        Payload payload = new Payload(jwtClaimsSet.toJSONObject());

        JWSObject jwsObject = new JWSObject(header, payload);

        try {
            jwsObject.sign(new MACSigner(SignerKey.getBytes()));
            return jwsObject.serialize();
        } catch (JOSEException e) {
            log.error("JWT Exception", e);
            throw new RuntimeException(e);
        }
    }
    public AuthenticationResponse refeshToken(RefeshRequest request) throws ParseException, JOSEException {
            var SingJWT = VerifyToken(request.getToken(),true);

            var jit = SingJWT.getJWTClaimsSet().getJWTID();

            var expirationTime = SingJWT.getJWTClaimsSet().getExpirationTime();

            InvalidatedToken invalidatedToken = InvalidatedToken.builder()
                    .id(jit)
                    .expiryTime(expirationTime)
                    .build();

            invalidatedTokenRepository.save(invalidatedToken);

            var u = SingJWT.getJWTClaimsSet().getSubject();

            var user = userRepository.findByEmail(u).orElseThrow(
                    () -> new AppException(ErrorCode.UNAUTHORIZED)
            );


        String token = generateToken(user);
        return  AuthenticationResponse.builder()
                .token(token)
                .authenticated(true)
                .build();
    }
    public void logout(LogoutRequest request) throws ParseException, JOSEException {
        try {
            SignedJWT signToken = VerifyToken(request.getToken(),false);

            String jit = signToken.getJWTClaimsSet().getJWTID();
            Date expiryTime = signToken.getJWTClaimsSet().getExpirationTime();

            InvalidatedToken invalidatedToken =
                    InvalidatedToken.builder().id(jit).expiryTime(expiryTime).build();

            invalidatedTokenRepository.save(invalidatedToken);
        }catch (AppException exception){
            log.info("Token already expired");
        };
    }
    public IntrospecResponsee Instropec(IntrospecRequest request) throws JOSEException, ParseException {

                boolean isValid = true;

                try{
                    VerifyToken(request.getToken(),false);
                }catch (AppException exception){
                    isValid = false;
                }

        return IntrospecResponsee.builder()
                .valid(isValid)
                .build();
    }

    private String buildScope(User user) {
        StringJoiner stringJoiner = new StringJoiner(" ");

        if (!CollectionUtils.isEmpty(user.getRoles()))
            user.getRoles().forEach(role -> {
                stringJoiner.add("ROLE_" + role.getName());
                if (!CollectionUtils.isEmpty(role.getPermissions()))
                    role.getPermissions().stream().filter(permission -> !permission.isDeleted()).forEach(permission -> stringJoiner.add(permission.getName()));
            });
        return stringJoiner.toString();
    }
    private SignedJWT VerifyToken(String token,boolean isRefesh) throws ParseException, JOSEException {
        JWSVerifier verifier = new MACVerifier(SignerKey.getBytes());

        SignedJWT signedJWT = SignedJWT.parse(token);

        //If isResh = true get ExpriTime to Refesh token
        //neu la refesh Expritime = GetissueTime +  REFRESHABLE_DURATION
        // neu ko phai resh expriTime = signedJWT.expritime
        Date expriTime = (isRefesh) ?
                new Date(signedJWT.getJWTClaimsSet().getIssueTime()
                        .toInstant().plus(REFRESHABLE_DURATION,ChronoUnit.SECONDS).toEpochMilli())
                : signedJWT.getJWTClaimsSet().getExpirationTime();

        var verified = signedJWT.verify(verifier);
        if(!(verified && expriTime.after(new Date()))) throw  new AppException(ErrorCode.UNAUTHENTICATED);
        if(invalidatedTokenRepository.existsById(signedJWT.getJWTClaimsSet().getJWTID()))
            throw new AppException(ErrorCode.UNAUTHENTICATED);

        return signedJWT;
    }

    public AuthenticationResponse outboundAuthenticate(String code){
        var response = outboundIdentityClient.exchangeToken(ExchangeTokenRequest.builder()
                        .code(code)
                        .clientId(OUTBOUND_IDENTITY_CLIENT_ID)
                        .redirectUri(OUTBOUND_IDENTITY_REDIRECT_URI)
                        .clientSecret(OUTBOUND_IDENTITY_CLIENT_SECRET)
                        .grantType(GRANT_TYPE)
                .build());


        var userInfo = outboundUserClient.GetUserInfo("json",response.getAccessToken());
        Set<Role> roles = new HashSet<>();
        roles.add(Role.builder()
                .name(PredefineRole.USER_ROLE)
                .build());

        var user = userRepository.findByEmail(userInfo.getEmail()).orElseGet(
                () -> userRepository.save(User.builder()
                                .firstName(userInfo.getGivenName())
                                .email(userInfo.getEmail())
                                .lastName(userInfo.getFamilyName())
                                .roles(roles)
                        .build())
        );

        //Onbard token Google -> systemToken

        var token = generateToken(user);

        log.info(RandomPasswordGenerator.generateRandomPassword(8));

        return AuthenticationResponse.builder()
                .authenticated(true)
                .token(token)
                .build();
    }
}
