package com.exemple.auth.payload.request;

import java.util.Set;

public class SignupRequest {
    private String username;
    private String email;
    private String password;
    private Set<String> roles;

    public String getUsername() {
        return username;
    }

    public String getEmail() {
        return email;
    }

    public String getPassword() {
        return password;
    }

    public Set<String> getRoles() {
        return roles;
    }
}
