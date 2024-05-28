package com.petrov.jwt.rest;


import com.petrov.jwt.dto.AuthenticationRequestDto;
import com.petrov.jwt.model.User;
import com.petrov.jwt.security.jwt.JwtTokenProvider;
import com.petrov.jwt.service.UserService;
import liquibase.exception.LockException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;



@RestController
@RequestMapping(value = "/api/v1/auth/")
@RequiredArgsConstructor
public class AuthenticationRestControllerV1 {

    private static final int MAX_FAILED_ATTEMPTS = 3;
    private final AuthenticationManager authenticationManager;

    private final JwtTokenProvider jwtTokenProvider;

    private final UserService userService;


    @PostMapping("login")
    public ResponseEntity login(@RequestBody AuthenticationRequestDto requestDto) {
        try {
            String username = requestDto.getUsername();
            User user = userService.findByUsername(username);

            if (user == null) {
                throw new UsernameNotFoundException("User with username: " + username + " not found");
            }

            if (user.getFailedAttempt() >= MAX_FAILED_ATTEMPTS) {
                if (userService.unlockWhenTimeExpired(user)) {
                    throw new LockException("Account is locked. Try again later.");
                }
            }

            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, requestDto.getPassword())
            );

            if (user.getFailedAttempt() > 0) {
                userService.resetFailedAttempts(username);
            }

            String token = jwtTokenProvider.generateToken(username, user.getRoles());

            Map<Object, Object> response = new HashMap<>();
            response.put("username", username);
            response.put("token", token);

            return ResponseEntity.ok(response);
        } catch (AuthenticationException e) {
            userService.increaseFailedAttempts(userService.findByUsername(requestDto.getUsername()));
            throw new BadCredentialsException("Invalid username or password");
        } catch (LockException e) {
            throw new RuntimeException(e);
        }
    }

}
