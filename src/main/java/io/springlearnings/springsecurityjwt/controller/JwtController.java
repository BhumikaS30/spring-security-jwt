package io.springlearnings.springsecurityjwt.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.springlearnings.springsecurityjwt.exception.MyBadCredentialsException;
import io.springlearnings.springsecurityjwt.security.JWTHelper;
import io.springlearnings.springsecurityjwt.model.JwtRequest;
import io.springlearnings.springsecurityjwt.model.JwtResponse;
import io.springlearnings.springsecurityjwt.service.CustomUserDetailsService;
import lombok.extern.slf4j.Slf4j;
import lombok.extern.slf4j.XSlf4j;

@RestController
@RequestMapping("/api/v1/auth")
@Slf4j
public class JwtController {

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Autowired
    private JWTHelper jwtHelper;

    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("/login")
    public ResponseEntity<JwtResponse> createToken(@RequestBody JwtRequest jwtRequest) throws MyBadCredentialsException {
        log.info("jwtRequest: {}", jwtRequest);
        authenticate(jwtRequest);
        UserDetails userDetails = this.customUserDetailsService.loadUserByUsername(jwtRequest.getUsername());
        String token = this.jwtHelper.generateToken(userDetails);
        log.info("JWT: {} ", token);

        return ResponseEntity.ok(new JwtResponse(token));
    }

    private void authenticate(JwtRequest jwtRequest) throws MyBadCredentialsException {
        try {
            this.authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(jwtRequest.getUsername(),
                                                                                            jwtRequest.getPassword()));
        } catch (BadCredentialsException e) {
            log.info("Invalid details");
            throw new MyBadCredentialsException("Invalid UserName/Password !!");
        }
    }

    @GetMapping("/welcome")
    public ResponseEntity<String> welcome() {
        return ResponseEntity.ok("Welcome this is a authorized page and is not allowed for view to unAuthorized users!");
    }

    @RequestMapping("/getusers")
    public String getUser() {
        return "{\"name\":\"Bhumika\"}";
    }
}
