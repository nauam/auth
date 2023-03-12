package com.exemple.auth.payload.response;

import com.exemple.auth.models.Role;
import com.exemple.auth.models.User;
import com.exemple.auth.models.enums.EToken;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class JwtResponse {
    private Long id;
    private String token;
    private EToken tokenType = EToken.BEARER;
    private String username;
    private String email;
    private List<String> roles;

}