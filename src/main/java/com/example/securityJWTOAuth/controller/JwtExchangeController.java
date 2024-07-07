package com.example.securityJWTOAuth.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;

@RestController
public class JwtExchangeController {

    @GetMapping("/tokenToHeader")
    public ResponseEntity<Void> tokenToHeader(HttpServletRequest request, HttpServletResponse response) {
        // 쿠키에서 "access" 값을 추출합니다.
        String accessToken = Arrays.stream(request.getCookies())
                .filter(cookie -> "access".equals(cookie.getName()))
                .map(cookie -> cookie.getValue())
                .findFirst()
                .orElse(null);

        if (accessToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
        }

        // HTTP 헤더에 "Authorization" 값을 추가
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", accessToken);

        Cookie cookie = new Cookie("refresh", null);
        cookie.setMaxAge(0);
        cookie.setPath("/");

        response.addCookie(cookie);

        // 헤더를 포함한 응답을 반환합니다.
        return new ResponseEntity<>(headers, HttpStatus.OK);
    }
}
