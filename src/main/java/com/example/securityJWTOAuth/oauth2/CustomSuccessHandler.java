package com.example.securityJWTOAuth.oauth2;

import com.example.securityJWTOAuth.dto.CustomOAuth2User;
import com.example.securityJWTOAuth.entity.Refresh;
import com.example.securityJWTOAuth.jwt.JWTUtil;
import com.example.securityJWTOAuth.repository.RefreshRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;

@Component
@RequiredArgsConstructor
public class CustomSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        //OAuth2User
        CustomOAuth2User customUserDetails = (CustomOAuth2User) authentication.getPrincipal();

        String username = customUserDetails.getUsername();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

        //토큰생성
        String access = jwtUtil.createJwt("access",username,role, 600000L);
        String refresh = jwtUtil.createJwt("refresh",username,role, 86400000L);

        //Refresh 토큰 저장
        refreshRepository.save(new Refresh(username, refresh));


        response.addCookie(jwtUtil.createCookie("access",access));
        response.addCookie(jwtUtil.createCookie("refresh",refresh));
        response.sendRedirect("http://localhost:8080/cookieToheader");
        //front에서 쿠키에있는 access Token를 헤더로 받아오도록 하려고 했지만 httponly설정...
    }

}
