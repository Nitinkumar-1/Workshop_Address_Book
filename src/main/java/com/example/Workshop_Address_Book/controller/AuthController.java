
package com.example.Workshop_Address_Book.controller;

import com.example.Workshop_Address_Book.dto.UserDTO;
import com.example.Workshop_Address_Book.service.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private UserService userService;

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@Valid @RequestBody UserDTO userDTO) {
        return ResponseEntity.ok(userService.registerUser(userDTO));
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> loginUser(@RequestBody Map<String, String> loginRequest) {
        String token = userService.loginUser(loginRequest.get("email"), loginRequest.get("password"));
        return ResponseEntity.ok(Map.of("token", token));
    }
}
