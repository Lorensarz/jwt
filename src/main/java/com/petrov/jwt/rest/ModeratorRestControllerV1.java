package com.petrov.jwt.rest;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/api/v1/moderator/")
@RequiredArgsConstructor
public class ModeratorRestControllerV1 {

    @GetMapping(value = "moderated")
    public ResponseEntity<String> getModeratedContent() {
        return new ResponseEntity<>("Content for moderators only", HttpStatus.OK);
    }
}
