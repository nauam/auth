package com.exemple.auth.service;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import com.exemple.auth.models.enums.EToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.exemple.auth.models.enums.ERole;
import com.exemple.auth.models.Token;
import com.exemple.auth.models.Role;
import com.exemple.auth.models.User;
import com.exemple.auth.payload.request.LoginRequest;
import com.exemple.auth.payload.request.SignupRequest;
import com.exemple.auth.payload.response.JwtResponse;
import com.exemple.auth.payload.response.MessageResponse;
import com.exemple.auth.repository.TokenRepository;
import com.exemple.auth.repository.RoleRepository;
import com.exemple.auth.repository.UserRepository;
import com.exemple.auth.security.jwt.JwtUtils;
import org.springframework.stereotype.Service;

@Service
public class AuthService {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    TokenRepository tokenRepository;

    public ResponseEntity<?> authenticate(LoginRequest loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        var user = (User) authentication.getPrincipal();
        String jwt = jwtUtils.generateToken(user);

        revokeAllUserTokens(user);
        saveUserToken(user, jwt);

        List<String> roles = getStrRoles(user.getAuthorities());

        return ResponseEntity.ok(JwtResponse
                .builder()
                .id(user.getId())
                .email(user.getEmail())
                .username(user.getUsername())
                .tokenType(EToken.BEARER)
                .roles(roles)
                .token(jwt)
                .build());
    }

    public ResponseEntity<?> register(SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }

        var user = User.builder()
                .username(signUpRequest.getUsername())
                .email(signUpRequest.getEmail())
                .password(encoder.encode(signUpRequest.getPassword()))
                .roles(getRoles(signUpRequest.getRoles()))
                .build();

        var jwt = jwtUtils.generateToken(user);
        user = userRepository.save(user);

        saveUserToken(user, jwt);

        List<String> roles = getStrRoles(user.getAuthorities());

        return ResponseEntity.ok(JwtResponse
                .builder()
                .id(user.getId())
                .email(user.getEmail())
                .username(user.getUsername())
                .tokenType(EToken.BEARER)
                .roles(roles)
                .token(jwt)
                .build());

    }

    private void saveUserToken(User user, String jwtToken) {
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(EToken.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }

    private void revokeAllUserTokens(User user) {
        var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        if (validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }

    private List<String> getStrRoles(Collection<? extends GrantedAuthority> roles) {
        return roles.stream().map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
    }

    private Set<Role> getRoles(Set<String> strRoles) {
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);

                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);

                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }
        return roles;
    }

}
