package com.example.securityJWTOAuth.repository;

import com.example.securityJWTOAuth.entity.Refresh;
import com.example.securityJWTOAuth.entity.Refresh;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

public interface RefreshRepository extends JpaRepository<Refresh,Long> {

    Boolean existsByRefresh(String refresh);

    @Transactional
    public void deleteByRefresh(String refresh);
}
