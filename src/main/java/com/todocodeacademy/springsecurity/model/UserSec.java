package com.todocodeacademy.springsecurity.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name="users")
@Getter @Setter
@AllArgsConstructor
@NoArgsConstructor
public class UserSec {
    @Id
    @GeneratedValue(strategy= GenerationType.IDENTITY)
    private Long id;
    @Column(unique = true)
    private String username;
    private String password;

    private boolean enabled;
    private boolean accountNotExpired;
    private boolean accountNotLocked;
    private boolean credentialNotExpired;

    //Usamos Set porque no permite repetidos
    //List permite repetidos
    @ManyToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL) //el eager me va  a cargar todos los roles
    @JoinTable (name = "user_roles", joinColumns = @JoinColumn(name = "user_id"),
    inverseJoinColumns=@JoinColumn(name = "role_id"))
    private Set<Role> rolesList = new HashSet<>();


}
