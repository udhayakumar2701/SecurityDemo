package com.security.example.demo.ErrorHandling;


import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import java.io.IOException;

    @Component
    public class CustomLoginErrorHandiling implements AuthenticationFailureHandler {

        @Override
        public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // Set status to 401 Unauthorized
            response.setContentType("application/json");

            String errorMessage;
            if (exception instanceof BadCredentialsException) {
                errorMessage = "Invalid username or password";
            } else {
                errorMessage = "Authentication failed";
            }

            // Send a custom error response in JSON format
            response.getWriter().write("{\"error\": \"" + errorMessage + "\"}");
        }
    }


