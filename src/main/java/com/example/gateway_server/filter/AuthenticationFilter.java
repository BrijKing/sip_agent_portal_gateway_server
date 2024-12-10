package com.example.gateway_server.filter;

import java.nio.charset.StandardCharsets;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;

import com.example.gateway_server.utils.JwtUtils;
import com.example.gateway_server.validator.RouteValidator;

import io.jsonwebtoken.ExpiredJwtException;
import reactor.core.publisher.Mono;

@Component
public class AuthenticationFilter  extends AbstractGatewayFilterFactory<AuthenticationFilter.Config>{

    @Autowired
    private RouteValidator validator;

    @Autowired
    private JwtUtils jwtUtils;

    public AuthenticationFilter(){
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            ServerHttpRequest request = null;
            if (validator.isSecured.test(exchange.getRequest())){
                if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)){
                    ServerHttpResponse response = exchange.getResponse();
                    response.setStatusCode(HttpStatus.UNAUTHORIZED);
                    byte[] responseBytes = "JWT token not found".getBytes(StandardCharsets.UTF_8);
					DataBuffer buffer = response.bufferFactory().wrap(responseBytes);
					return response.writeWith(Mono.just(buffer));

                }

                String authHeader = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
                if (authHeader != null && authHeader.startsWith("Bearer ")) {
					authHeader = authHeader.substring(7);
				}
                try {
                    jwtUtils.validToken(authHeader);
					
					request = exchange.getRequest().mutate().header("loggedInUser", jwtUtils.extractEmail(authHeader).getSubject()).build();
                } catch (ExpiredJwtException e) {
                    // TODO: handle exception
                    ServerHttpResponse response = exchange.getResponse();
					response.setStatusCode(HttpStatus.UNAUTHORIZED);
					byte[] responseBytes = "your token has been expired please login again !!"
							.getBytes(StandardCharsets.UTF_8);
					DataBuffer buffer = response.bufferFactory().wrap(responseBytes);
					return response.writeWith(Mono.just(buffer));
                }
                catch(Exception e){
                    ServerHttpResponse response = exchange.getResponse();
					response.setStatusCode(HttpStatus.UNAUTHORIZED);
					byte[] responseBytes = "Unauthorized access to the application".getBytes(StandardCharsets.UTF_8);
					DataBuffer buffer = response.bufferFactory().wrap(responseBytes);
					return response.writeWith(Mono.just(buffer));
                }
            }

            return chain.filter(exchange.mutate().request(request).build());
        });
    }

    public static class Config {

	}
}