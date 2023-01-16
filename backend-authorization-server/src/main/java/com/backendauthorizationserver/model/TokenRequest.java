package com.backendauthorizationserver.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.stereotype.Component;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Component
public class TokenRequest {
    private String clientId;
    private String clientSecret;
    private String grantType;

}
