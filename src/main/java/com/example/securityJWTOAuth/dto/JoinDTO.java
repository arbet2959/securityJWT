package com.example.securityJWTOAuth.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class JoinDTO {

    private String username;
    private String name;
    private String password;
    private String email;
}
