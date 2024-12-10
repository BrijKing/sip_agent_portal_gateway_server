package com.example.gateway_server.validator;

import java.util.List;
import java.util.function.Predicate;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

@Component
public class RouteValidator {

    public static final List<String> openApiEndpoints = List.of(
	            "/api/auth/registerUser",
	            "/api/auth/loginUser",
	            "/eureka"
	    );

    public Predicate<ServerHttpRequest> isSecured =
        request -> openApiEndpoints
                .stream()
                .noneMatch(uri -> request.getURI().getPath().equals(uri));
    
}