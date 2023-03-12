package com.exemple.auth.service;

import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

import com.exemple.auth.models.enums.EToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
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
        revokeAllUserTokens(user);
        return response(user);
    }

    public ResponseEntity<?> register(SignupRequest signUpRequest) {
        try {
            if (userRepository.existsByUsername(signUpRequest.getUsername()))
                return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));

            if (userRepository.existsByEmail(signUpRequest.getEmail()))
                return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));

            var user = User.builder().username(signUpRequest.getUsername()).email(signUpRequest.getEmail())
                    .password(encoder.encode(signUpRequest.getPassword())).roles(getRoles(signUpRequest.getRoles())).build();

            user = userRepository.save(user);
            return response(user);
        } catch (IllegalArgumentException e){
            return ResponseEntity.badRequest().body(new MessageResponse(e.getMessage()));
        }
    }

    private static final Map<String, Function<RoleRepository, Optional<Role>>> ROLE_MAPPINGS = Map.of(
            "admin", roleRepository -> roleRepository.findByName(ERole.ROLE_ADMIN),
            "mod", roleRepository -> roleRepository.findByName(ERole.ROLE_MODERATOR),
            "user", roleRepository -> roleRepository.findByName(ERole.ROLE_USER)
    );

    private ResponseEntity<?> response(User user) {
        try {
            var jwt = jwtUtils.generateToken(user);
            saveUserToken(user, jwt);
            List<String> roles = getStrRoles(user.getAuthorities());
            return ResponseEntity.ok(JwtResponse.builder().id(user.getId()).email(user.getEmail())
                    .username(user.getUsername()).tokenType(EToken.BEARER).roles(roles).token(jwt).build());
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new MessageResponse(e.getMessage()));
        }
    }

    private List<String> getStrRoles(Collection<? extends GrantedAuthority> roles) {
        return roles.stream().map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
    }

    private Set<Role> getRoles(Set<String> strRoles) {
        return strRoles == null ? Set.of(roleMappings("user")) :
                strRoles.stream().map(this::roleMappings).collect(Collectors.toSet());
    }

    private Role roleMappings(String role) {
        return ROLE_MAPPINGS
                .getOrDefault(role, (roleRepository) -> Optional.empty())
                .apply(roleRepository)
                .orElseThrow(() -> new IllegalArgumentException("Error: Role is not found."));
    }

    private void saveUserToken(User user, String jwtToken) {
        var token = Token.builder().user(user).token(jwtToken).tokenType(EToken.BEARER).expired(false).revoked(false).build();
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

}
