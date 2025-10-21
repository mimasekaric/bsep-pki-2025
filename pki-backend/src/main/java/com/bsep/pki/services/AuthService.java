package com.bsep.pki.services;

import com.bsep.pki.dtos.requests.LoginRequestDTO;
import com.bsep.pki.dtos.requests.UserRegistrationDTO;
import com.bsep.pki.dtos.responses.LoginResponseDTO;
import com.bsep.pki.dtos.responses.UserResponseDTO;
import com.bsep.pki.services.interfaces.IAuthService;
import com.bsep.pki.services.interfaces.IUserService;
import com.bsep.pki.util.AuditLog;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.stream.Collectors;

@Service
public class AuthService implements IAuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtEncoder jwtEncoder;
    private final IUserService userService;

    @Value("${app.jwt.expiration}")
    private long jwtExpirySeconds;

    public AuthService(AuthenticationManager authenticationManager,
                       JwtEncoder jwtEncoder,
                       IUserService userService) {
        this.authenticationManager = authenticationManager;
        this.jwtEncoder = jwtEncoder;
        this.userService = userService;
    }

    @Override
    @AuditLog(action = "TRIED_LOGIN")
    public ResponseEntity<LoginResponseDTO> login(LoginRequestDTO loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword())
        );

        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .expiresAt(now.plus(jwtExpirySeconds, ChronoUnit.SECONDS))
                .subject(authentication.getName())
                .claim("scope", authentication.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.joining(" ")))
                .build();

        JwsHeader jwsHeader = JwsHeader.with(MacAlgorithm.HS256).build();

        JwtEncoderParameters encoderParameters = JwtEncoderParameters.from(jwsHeader, claims);

        String token = this.jwtEncoder.encode(encoderParameters).getTokenValue();

        return ResponseEntity.ok(new LoginResponseDTO(token, authentication.getName()));
    }

    @Override
    @AuditLog(action = "TRIED_REGISTER")
    public ResponseEntity<UserResponseDTO> register(UserRegistrationDTO dto) {
        UserResponseDTO user = userService.registerUser(dto);
        return new ResponseEntity<>(user, HttpStatus.CREATED);
    }


}
