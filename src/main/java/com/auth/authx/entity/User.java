package com.authx.entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.Set;

@Data
@Entity
@Table(name = "users")
public class User {
    @Id()
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = false)
    private String password;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_roles", // Join on user_roles junction table
            joinColumns = @JoinColumn(name = "user_id"), // current table column id mapped to user_id
            inverseJoinColumns = @JoinColumn(name = "role_id") // other table column id mapped to role_id
    )
    private Set<Role> roles;

    private Boolean enabled = true;
}