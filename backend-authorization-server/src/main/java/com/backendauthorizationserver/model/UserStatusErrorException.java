package com.backendauthorizationserver.model;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class UserStatusErrorException {

    private String transactionId;
    private String status;
    private String description;
    private String redirectUrl;
    private String title;

    public UserStatusErrorException(String transactionId, String status, String description, String redirectUrl, String title) {
        this.transactionId = transactionId;
        this.status = status;
        this.description = description;
        this.redirectUrl = redirectUrl;
        this.title = title;
    }
}
