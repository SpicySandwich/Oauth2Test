package com.backendauthorizationserver.controller;

import com.backendauthorizationserver.enumhelper.TokenField;
import com.backendauthorizationserver.model.TokenRequest;
import com.backendauthorizationserver.model.TokenResponse;
//import com.backendauthorizationserver.utility.UrlUtility;
import com.google.gson.Gson;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import org.springframework.web.util.UriComponentsBuilder;



@RestController
public class controllertest {

    @Autowired
    private ProviderSettings providerSettings;

    @Autowired
    private RestTemplate restTemplate;


    String url = "http://localhost:8080";

//    @Autowired
//    private UrlUtility urlUtility;

//    @GetMapping("/test")
//    public String returnStringNeedToken(){
//        return urlUtility.portDomain();
//    }



    @GetMapping("/testname2")
    public String returnStringParamExcluded2(@RequestParam String firstname
//            ,@RequestParam String lastname
    ){
        return firstname ;
    }


    @GetMapping("/testname/{firstname}")
    public String returnStringParamExcluded(@PathVariable String firstname){
        return firstname ;
    }

//    @GetMapping("/testname")
//    public String returnStringParamExcluded(@RequestParam String firstname,@RequestParam String lastname){
//        return firstname +" "+lastname;
//    }

    @PostMapping("/excludedForSecurity")
    public String returnStringExcluded(){
        System.out.println(providerSettings.getTokenEndpoint());
        return "Conred";
    }


    @PostMapping("/generateToken")
    public ResponseEntity<TokenResponse> token(@RequestBody TokenRequest tokenRequest){
        Gson gson = new Gson();
        UriComponentsBuilder builderURL = UriComponentsBuilder.fromHttpUrl(url+providerSettings.getTokenEndpoint())
                .queryParam(TokenField.client_id.toString(), tokenRequest.getClientId())
                .queryParam(TokenField.client_secret.toString(), tokenRequest.getClientSecret())
                .queryParam(TokenField.grant_type.toString(), tokenRequest.getGrantType());

      String responseToken = restTemplate.postForObject(builderURL.toUriString(), HttpEntity.class,String.class);
        TokenResponse tokenResponse =  gson.fromJson(responseToken, TokenResponse.class);
      return new ResponseEntity<>(tokenResponse, HttpStatus.OK);
    }



}
