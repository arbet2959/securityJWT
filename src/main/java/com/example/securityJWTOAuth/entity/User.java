package com.example.securityJWTOAuth.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Getter @Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User {


    public User(String username, String name, String email, RoleType role) {
        this.username = username;
        this.name = name;
        this.email = email;
        this.role = role;
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;
    private String name;
    private String password;
    private String email;
    @Enumerated(value = EnumType.STRING)
    private RoleType role;
}
