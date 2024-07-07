package com.example.securityJWTOAuth.controller;


import com.example.securityJWTOAuth.entity.Refresh;
import com.example.securityJWTOAuth.jwt.JWTUtil;
import com.example.securityJWTOAuth.repository.RefreshRepository;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.util.Arrays;

@RestController
@RequiredArgsConstructor
public class ReissueController {

    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response){
        //get refresh token
        Cookie[] cookies = request.getCookies();
        String refresh = Arrays.stream(cookies)
                .filter(cookie -> cookie.getName().equals("refresh"))
                .map(cookie -> cookie.getValue())
                .findFirst()
                .orElse(null);

        if (refresh == null) {
            String redirectUrl = "http://localhost:8080/login";
            HttpHeaders headers = new HttpHeaders();
            headers.setLocation(URI.create(redirectUrl));

            return new ResponseEntity<>(headers, HttpStatus.TEMPORARY_REDIRECT); //REDIRECT LOGIN 307? or 401
        }

        //expired check
        try {
            jwtUtil.isExpired(refresh);
        } catch (ExpiredJwtException e) {

            String redirectUrl = "http://localhost:8080/login";
            HttpHeaders headers = new HttpHeaders();
            headers.setLocation(URI.create(redirectUrl));

            return new ResponseEntity<>(headers, HttpStatus.TEMPORARY_REDIRECT); //REDIRECT LOGIN
        }

        // 토큰이 refresh인지 확인 (발급시 페이로드에 명시)
        String category = jwtUtil.getCategory(refresh);
        if (!category.equals("refresh")) {
            //response status code
            return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST);
        }
        //DB에 저장되어 있는지 확인
        Boolean isExist = refreshRepository.existsByRefresh(refresh);
        if (!isExist) {
            //response status code
            return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST);
        }

        String username = jwtUtil.getUsername(refresh);
        String role = jwtUtil.getRole(refresh);

        //토큰생성
        String newAccess = jwtUtil.createJwt("access",username,role, 60*10*1000L);
        String newRefresh = jwtUtil.createJwt("refresh",username,role, 24*60*60*1000L);

        //기존 Refresh 토큰 삭제후 새토큰저장
        refreshRepository.deleteByRefresh(refresh);
        refreshRepository.save(new Refresh(username, newRefresh));

        //응답생성
        response.setHeader("Authorization",newAccess);
        response.addCookie(jwtUtil.createCookie("refresh",newRefresh));

        return new ResponseEntity<>(HttpStatus.OK);
    }

}

