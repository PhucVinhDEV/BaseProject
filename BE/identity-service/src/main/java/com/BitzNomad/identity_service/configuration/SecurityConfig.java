package com.BitzNomad.identity_service.configuration;

import com.BitzNomad.identity_service.Service.AuthenticationService2;
import com.BitzNomad.identity_service.Service.RedisService;
import com.BitzNomad.identity_service.repository.UserRepository;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import lombok.RequiredArgsConstructor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import javax.crypto.spec.SecretKeySpec;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final String[] PUBLIC_ENDPONIT = {"/api/user","/auth/login"
            ,"/auth/logout","/auth/instrospec","/auth/refesh",
            "/auth/outbound/authentication","/user/myinfo"};

    // phai dc tat truoc khi public Error *********************************
    private final String[] PUBLIC_SWAGGER = {"/swagger-ui/*","/swagger-ui-custom.html"
            , "/v3/api-docs/*", "/api-docs/*","/api-docs"};
    private final String[] GET_PUBLIC_ENDPONIT = {"/api/user"};

    @Value("${jwt.secretKey}")
    private String SignerKey;

    private final CustomJwtDecoder customJwtDecoder;
    private final UserRepository userRepository;
    private final RedisService redisService;
    private final AuthenticationService2 authenticateService;
    @Bean
    public SecurityFilterChain filterChain( HttpSecurity httpSecurity) throws Exception {
        // Thêm RedisJwtAuthenticationFilter vào trước các filter hiện tại
        httpSecurity.addFilterBefore(redisJwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        //Config endponit authentication
        httpSecurity.authorizeRequests(request -> request
                        .requestMatchers(HttpMethod.POST,PUBLIC_ENDPONIT).permitAll()
                .requestMatchers(PUBLIC_SWAGGER).permitAll() // Công khai các đường dẫn Swagger
                .anyRequest().authenticated());

        //config oauth2
                httpSecurity.oauth2ResourceServer(oauth2 ->
                    oauth2.jwt(jwtConfigurer -> jwtConfigurer.decoder(jwtDecoder())
                            .jwtAuthenticationConverter(jwtAuthenticationConverter())
                    ).authenticationEntryPoint(new JwtAuthenticationEntryPoint()));


                httpSecurity.csrf(AbstractHttpConfigurer::disable);

        return httpSecurity.build();
    }

    @Bean
    JwtDecoder jwtDecoder() {
        SecretKeySpec signingKey = new SecretKeySpec(SignerKey.getBytes(), "HS512");
       return NimbusJwtDecoder.withSecretKey(signingKey)
               .macAlgorithm(MacAlgorithm.HS512)
               .build();
    }
    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        jwtGrantedAuthoritiesConverter.setAuthorityPrefix("");

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);

        return jwtAuthenticationConverter;
    }
    @Bean
    public RedisJwtAuthenticationFilter redisJwtAuthenticationFilter() {
        return new RedisJwtAuthenticationFilter(authenticateService,userRepository,redisService); // Assuming this is your custom filter
    }

    @Bean
    public CorsFilter corsFilter(){
        CorsConfiguration config = new CorsConfiguration();

        config.addAllowedOrigin("http://localhost:3000");
        config.addAllowedMethod("*");
        config.addAllowedHeader("*");

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }

}
