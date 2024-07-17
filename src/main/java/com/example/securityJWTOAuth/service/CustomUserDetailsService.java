package com.example.securityJWTOAuth.service;

import com.example.securityJWTOAuth.dto.CustomUserDetails;
import com.example.securityJWTOAuth.entity.User;
import com.example.securityJWTOAuth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    
    private final UserRepository userRepository;
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Optional<User> userOptional = userRepository.findByUsername(username);


        return userOptional
                .map(user -> new CustomUserDetails(user.getUsername(), user.getRole().toString()))
                .orElse(null);
    }
}
