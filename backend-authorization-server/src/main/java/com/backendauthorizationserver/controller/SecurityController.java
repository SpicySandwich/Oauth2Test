package com.backendauthorizationserver.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController

@RequestMapping("/mini")
public class SecurityController {

    @GetMapping("/checkStatus")
    public ResponseEntity<String> checkUserStatus(@RequestParam(value = "authCode", required = false) String authCode, @RequestParam(value = "transactionId", required = false) String transactionId, @RequestHeader Map<String, Object> requestHeaders) throws Exception {
        return new ResponseEntity<>("Conred", HttpStatus.OK);
    }

}
