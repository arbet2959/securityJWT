package com.example.securityJWTOAuth.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Entity
@Getter @Setter
public class Refresh {
    protected Refresh() {
    }

    public Refresh(String username, String refresh) {

        this.username = username;
        this.refresh = refresh;
        this.expiration = new Date(System.currentTimeMillis()+86400000L).toString();
    }

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;
    private String refresh;
    private String expiration;
}
