package com.todocodeacademy.springsecurity.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class JwtUtils {
    // aca va codigo para jwt
    @Value("${security.jwt.private.key}")
    private String privateKey;
    @Value("${security.jwt.user.generator}")
    private String userGenerator;

    // creacion del token
    public String createToken (Authentication  authentication) {

        Algorithm algorithm = Algorithm.HMAC256(privateKey);
        // queda en el context holder
        String username = authentication.getPrincipal().toString();

        String authorities = authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        String jwtToken = JWT.create()
                .withIssuer(this.userGenerator) // encargador de generar el token
                .withSubject(username) // usuario que sera guardado dentro de los claims;
                .withClaim("authorities",authorities)
                .withIssuedAt(new Date()) // fecha de creacion del token
                .withExpiresAt(new Date(System.currentTimeMillis() + 1800000 )) // tiempo de expiracion del token (30m)
                .withJWTId(UUID.randomUUID().toString())
                .withNotBefore(new Date(System.currentTimeMillis()))  // A partir de cuando es valido el token
                .sign(algorithm);

        return jwtToken;
    }

    // decodificar y validar nuestros token
    public DecodedJWT validateToken (String token){
        try {
            Algorithm algorithm = Algorithm.HMAC256(privateKey);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer(this.userGenerator)
                    .build();
            // si todo esta ok no genera ninguna excepcion y nos devuelve el JWT decodificado
            DecodedJWT decodedJWT = verifier.verify(token);
            return decodedJWT;
        } catch (JWTVerificationException exception){
            throw new JWTVerificationException("Invalid token. Not authorized");
        }
    }

    // Obtener el usuario/username de nuestro token
    public String extractUsername (DecodedJWT decodedJWT) {
        return decodedJWT.getSubject().toString();
    }

    // Obtener un claim en particular de nuestro token
    public Claim getSprecificClaim (DecodedJWT decodedJWT,String claimName) {
        return decodedJWT.getClaim(claimName);
    }


    // Obtener los claims de nuestro token
    public Map<String,Claim> returnAllClaim (DecodedJWT decodedJWT) {
        return decodedJWT.getClaims();
    }


}
