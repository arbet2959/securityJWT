package com.example.securityJWTOAuth.service;

import com.example.securityJWTOAuth.entity.RoleType;
import com.example.securityJWTOAuth.entity.User;
import com.example.securityJWTOAuth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    UserRepository userRepository;

    @Transactional
    public User createOrUpdateUser(Optional<User> userEntityOptional, String email, RoleType role, String username, String name) {
        return userEntityOptional
                .map(userEntity ->{
                    userEntity.setEmail(email);
                    userEntity.setRole(role);
                    userEntity.setName(name);
                    return userEntity;
                })
                .orElseGet(()-> {
                    User newUserEntity = new User(username, name, email, role);
                    return userRepository.save(newUserEntity);
                });
    }
}
