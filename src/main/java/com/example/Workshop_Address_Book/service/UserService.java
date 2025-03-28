
package com.example.Workshop_Address_Book.service;

import com.example.Workshop_Address_Book.dto.UserDTO;
import com.example.Workshop_Address_Book.model.User;
import com.example.Workshop_Address_Book.repository.UserRepository;
import com.example.Workshop_Address_Book.security.JwtUtil;
import com.example.Workshop_Address_Book.security.PasswordEncoderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoderService passwordEncoderService;

    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private PasswordEncoder passwordEncoder;

    public String registerUser(UserDTO userDTO) {
        if (userRepository.findByEmail(userDTO.getEmail()).isPresent()) {
            throw new RuntimeException("Email already exists");
        }

        User user = new User();
        user.setName(userDTO.getName());
        user.setEmail(userDTO.getEmail());
        user.setPassword(passwordEncoderService.encodePassword(userDTO.getPassword()));
        user.setRole("USER");

        userRepository.save(user);
        return "User registered successfully!";
    }

    public String loginUser(String email, String password) {
        Optional<User> userOpt = userRepository.findByEmail(email);
        if (userOpt.isEmpty() || !passwordEncoderService.matches(password, userOpt.get().getPassword())) {
            throw new RuntimeException("Invalid email or password");
        }

        return jwtUtil.generateToken(email);
    }
    public boolean existsByEmail(String email) {
        return userRepository.findByEmail(email).isPresent();
    }

    public void updatePassword(String email, String newPassword) {
        Optional<User> optionalUser = userRepository.findByEmail(email);
        if (optionalUser.isPresent()) {
            User user = optionalUser.get();
            user.setPassword(passwordEncoder.encode(newPassword));
            userRepository.save(user);
        }
    }
}
