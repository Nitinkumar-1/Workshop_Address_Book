package com.example.Workshop_Address_Book.controller;

import com.example.Workshop_Address_Book.dto.UserDTO;
import com.example.Workshop_Address_Book.security.JwtUtil;
import com.example.Workshop_Address_Book.service.EmailService;
import com.example.Workshop_Address_Book.service.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private UserService userService;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private EmailService emailService;

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@Valid @RequestBody UserDTO userDTO) {
        String response = userService.registerUser(userDTO);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> loginUser(@RequestBody Map<String, String> loginRequest) {
        String email = loginRequest.get("email");
        String password = loginRequest.get("password");

        if (email == null || password == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "Email and password are required"));
        }

        String token = userService.loginUser(email, password);
        return ResponseEntity.ok(Map.of("token", token));
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        if (email == null || !userService.existsByEmail(email)) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found!");
        }

        String resetToken = jwtUtil.generateToken(email);
        emailService.sendResetEmail(email, resetToken);

        return ResponseEntity.ok("Password reset link sent!");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@RequestParam("token") String token, @RequestBody Map<String, String> request) {
        if (token == null || !jwtUtil.validateToken(token)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid or expired token!");
        }

        String email = jwtUtil.extractEmailFromToken(token);
        String newPassword = request.get("password");

        if (newPassword == null || newPassword.isBlank()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("New password cannot be empty!");
        }

        userService.updatePassword(email, newPassword);
        return ResponseEntity.ok("Password updated successfully!");
    }
}
