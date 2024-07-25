package com.todocodeacademy.springsecurity.service;
import com.todocodeacademy.springsecurity.dto.AuthLoginRequestDTO;
import com.todocodeacademy.springsecurity.dto.AuthResponseDTO;
import com.todocodeacademy.springsecurity.model.Permission;
import com.todocodeacademy.springsecurity.model.Role;
import com.todocodeacademy.springsecurity.model.UserSec;
import com.todocodeacademy.springsecurity.repository.IUserRepository;
import com.todocodeacademy.springsecurity.utils.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class UserDetailsServiceImp implements UserDetailsService {

    @Autowired
    private IUserRepository userRepo;
    @Autowired
    private JwtUtils jwtUtils;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername (String username) throws UsernameNotFoundException {

        //tenemos User sec y necesitamos devolver UserDetails
        //traemos el usuario de la bd
        UserSec userSec = userRepo.findUserEntityByUsername(username)
                .orElseThrow(()-> new UsernameNotFoundException("El usuario " + username + "no fue encontrado"));

        //con GrantedAuthority Spring Security maneja permisos
        List<SimpleGrantedAuthority> authorityList = new ArrayList<>();

        //Programación funcional a full
        //tomamos roles y los convertimos en SimpleGrantedAuthority para poder agregarlos a la authorityList
        userSec.getRolesList()
                .forEach(role -> authorityList.add(new SimpleGrantedAuthority("ROLE_".concat(role.getRole()))));


        //ahora tenemos que agregar los permisos
        userSec.getRolesList().stream()
                .flatMap(role -> role.getPermissionsList().stream()) //acá recorro los permisos de los roles
                .forEach(permission -> authorityList.add(new SimpleGrantedAuthority(permission.getPermissionName())));

        //retornamos el usuario en formato Spring Security con los datos de nuestro userSec
        return new User(userSec.getUsername(),
                userSec.getPassword(),
                userSec.isEnabled(),
                userSec.isAccountNotExpired(),
                userSec.isCredentialNotExpired(),
                userSec.isAccountNotLocked(),
                authorityList);
    }

    public AuthResponseDTO loginUser(AuthLoginRequestDTO authLoginRequestDTO) {

        // Recuperamos el nombre de ususario y la contraseña
        String username = authLoginRequestDTO.username();
        String password = authLoginRequestDTO.password();

        Authentication authentication = this.authenticate(username,password);

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String accessToken = jwtUtils.createToken(authentication);

        AuthResponseDTO authResponseDTO = new AuthResponseDTO(username,"Login successfull", accessToken,true);
        return authResponseDTO;
    }

    private Authentication authenticate(String username, String password) {
        UserDetails userDetails = this.loadUserByUsername(username);

        if(userDetails==null) {
            throw new BadCredentialsException("Invalid username or password");
        }
        if(!passwordEncoder.matches(password,userDetails.getPassword())) {
            throw new BadCredentialsException("Invalid username or password");
        }
        return new UsernamePasswordAuthenticationToken(username,userDetails.getPassword(),userDetails.getAuthorities());
    }
}
