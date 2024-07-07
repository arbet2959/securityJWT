package com.example.securityJWTOAuth.config;

import com.example.securityJWTOAuth.jwt.CustomLogoutFilter;
import com.example.securityJWTOAuth.jwt.JWTFilter;
import com.example.securityJWTOAuth.jwt.JWTUtil;
import com.example.securityJWTOAuth.oauth2.CustomSuccessHandler;
import com.example.securityJWTOAuth.repository.RefreshRepository;
import com.example.securityJWTOAuth.service.CustomOauth2UserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomOauth2UserService customOAuth2UserService;
    private final JWTUtil jwtUtil;
    private final CustomSuccessHandler customSuccessHandler;
    private final RefreshRepository refreshRepository;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{

        //csrf disable
        http.csrf((auth)->auth.disable());
        //form disable
        http.formLogin((auth)->auth.disable());
        //HTTP basic 인증방식 disable
        http.httpBasic((auth)->auth.disable());
        //cors 설정
        http.cors(corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {

                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {

                        CorsConfiguration configuration = new CorsConfiguration();

                        configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                        configuration.setAllowedMethods(Collections.singletonList("*"));
                        configuration.setAllowCredentials(true);
                        configuration.setAllowedHeaders(Collections.singletonList("*"));
                        configuration.setMaxAge(3600L);

                        configuration.setExposedHeaders(Collections.singletonList("Set-Cookie"));
                        configuration.setExposedHeaders(Collections.singletonList("Authorization"));

                        return configuration;
                    }
                }));

        http.addFilterAfter(new JWTFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class);
        http.addFilterAt(new CustomLogoutFilter(jwtUtil,refreshRepository), LogoutFilter.class);

        //OAuth2
        http.oauth2Login((oauth2) -> oauth2
                        .userInfoEndpoint((userInfoEndpointConfig) -> userInfoEndpointConfig
                                .userService(customOAuth2UserService))
                        .successHandler(customSuccessHandler));

        //경로별 인가
        http.authorizeHttpRequests((auth)->auth
                .requestMatchers("/login", "/", "/join").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
//                .requestMatchers("/oauth").hasRole("OAUTH")
                .requestMatchers("/reissue").permitAll()
                .anyRequest().authenticated());

        //세션 stateless 설정
        http.sessionManagement((session)->session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}
