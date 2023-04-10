package io.springlearnings.springsecurityjwt.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class JwtRequest {

    private String username;

    private String password;

    @Override
    public String toString() {
        return "JwtRequest{" +
               "userName='" + username + '\'' +
               ", password='" + password + '\'' +
               '}';
    }
}
