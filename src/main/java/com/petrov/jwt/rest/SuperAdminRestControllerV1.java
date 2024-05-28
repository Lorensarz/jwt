package com.petrov.jwt.rest;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/api/v1/super_admin/")
@RequiredArgsConstructor
public class SuperAdminRestControllerV1 {

    @PreAuthorize("hasRole('SUPER_ADMIN')")
    @GetMapping(value = "super_administrated")
    public ResponseEntity<String> getModeratedContent() {
        return new ResponseEntity<>("Content for super admin only", HttpStatus.OK);
    }


}
