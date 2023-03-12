package com.exemple.auth.models.enums;

public enum ERole {
    ROLE_USER,
    ROLE_MODERATOR,
    ROLE_ADMIN;

    public String getName() {
        return name();
    }
}
