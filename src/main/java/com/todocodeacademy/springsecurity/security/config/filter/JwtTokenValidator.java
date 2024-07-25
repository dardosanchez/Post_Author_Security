package com.todocodeacademy.springsecurity.security.config.filter;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.todocodeacademy.springsecurity.utils.JwtUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collection;

public class JwtTokenValidator extends OncePerRequestFilter {  // Se ejecuta cada vez que llena una request

    private JwtUtils  jwtUtils;

    public JwtTokenValidator(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    protected  void doFilterInternal (@NonNull HttpServletRequest request,
                                      @NonNull HttpServletResponse response,
                                      @NonNull FilterChain filterChain) throws ServletException, IOException {
        // Obtenemos el token de el header de la request
        String jwtToken = request.getHeader(HttpHeaders.AUTHORIZATION);

        if(jwtToken!=null) {
            // Sacamos el bearer + espacion en blanco del token BEARER mfkdsfkma
            jwtToken = jwtToken.substring(7);

            // Decodificamos el JWT
            DecodedJWT decodedJWT = jwtUtils.validateToken(jwtToken);

            // Extraemos el usuario y los permisos
            String username = jwtUtils.extractUsername(decodedJWT);
            String authorities = jwtUtils.getSprecificClaim(decodedJWT,"authorities").asString();

            // Llevamos todo al contextHolder y para eso tenemos que convertir todo en GrantedAuthority
            Collection<? extends GrantedAuthority> authoritiesList  = AuthorityUtils.commaSeparatedStringToAuthorityList(authorities);

            SecurityContext context = SecurityContextHolder.getContext();
            Authentication authentication = new UsernamePasswordAuthenticationToken(username,null,authoritiesList);
            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);
        }

        filterChain.doFilter(request,response);





    }

}
