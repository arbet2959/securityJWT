package com.example.securityJWTOAuth.service;

import com.example.securityJWTOAuth.dto.JoinDTO;
import com.example.securityJWTOAuth.entity.RoleType;
import com.example.securityJWTOAuth.entity.User;
import com.example.securityJWTOAuth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public void joinProcess(JoinDTO joinDTO) {

        String username = joinDTO.getUsername();
        String name = joinDTO.getName();
        String password = joinDTO.getPassword();
        String email = joinDTO.getEmail();

        Boolean isExist = userRepository.existsByUsername(username);

        if (isExist) {

            return;
        }

        User user = new User(username,name,bCryptPasswordEncoder.encode(password),email, RoleType.ROLE_USER);

        userRepository.save(user);
    }
}
