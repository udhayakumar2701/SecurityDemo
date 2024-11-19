package com.security.example.demo.Security;

import com.security.example.demo.ErrorHandling.CustomLoginErrorHandiling;
import com.security.example.demo.Service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration // Indicates that this class provides Spring configuration.
@EnableWebSecurity // Enables web security, which applies Spring Security settings to the application.
public class SpringSecurity {


    @Autowired
    // Injects an instance of the UserDetailsService interface. The customUserDetailsService will handle loading user-specific details during authentication.
    UserDetailsService customUserDetailsService;

    @Autowired
    CustomLoginErrorHandiling customLoginErrorHandiling;


    /**
     * Configures the HTTP security settings for the web application.
     *
     * @param security The HttpSecurity object used to configure the security settings for the HTTP requests.
     * @return SecurityFilterChain: A configured SecurityFilterChain to enforce the security settings.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity security) throws  Exception{
        security
                // Disables CSRF (Cross-Site Request Forgery) protection. In a production system, this should be enabled unless there is a specific reason to disable it.
               .csrf(csrf->csrf.disable())
                .cors(
                        Customizer.withDefaults()
                )// Enables CORS (Cross-Origin Resource Sharing) with default settings.
                .authorizeHttpRequests(
                        request->request// Configures authorization rules for HTTP requests.
                        .requestMatchers("/auth/login","/csrf").permitAll() // The "/login" endpoint is allowed to be accessed by anyone, no authentication required.
                        .anyRequest().authenticated()// Any other requests require authentication.
                )
                .formLogin(
                        login-> login // Configures the login page for the form-based login.
                        .loginPage("/auth/login")
                        .loginProcessingUrl("/login")
                        .failureHandler(authenticationFailureHandler()) // Customizes the login page URL. Users will be redirected here for authentication
                        .permitAll() // Ensures that the login page is accessible to everyone (no authentication needed).
                )
               // .formLogin(Customizer.withDefaults()) // Applies default login configuration settings.
                .logout(logout -> logout
                        .logoutUrl("/logout") // The default logout URL (POST request)
                        .logoutSuccessUrl("/login?logout=true") // Redirect to login page with logout=true after logout
                        .permitAll()) // Allow anyone to access the logout URL
              ;
        // Returns the configured SecurityFilterChain to apply the security settings.
        return security.build();
    }




    /**
     * This method defines a Spring Bean that provides an AuthenticationProvider.
     * It uses a DaoAuthenticationProvider to authenticate users based on a custom user details service.
     * The password encoding is set to NoOpPasswordEncoder, meaning passwords will be processed in plain text (this is not recommended for production).
     *
     * @return AuthenticationProvider: Returns a configured DaoAuthenticationProvider.
     */
    @Bean
    public AuthenticationProvider authenticationProvider(){
        // Create a new instance of DaoAuthenticationProvider, which is responsible for authenticating users.
        DaoAuthenticationProvider authentication = new DaoAuthenticationProvider();

        // Set the custom UserDetailsService to load user details (e.g., username, password, roles) for authentication.
        authentication.setUserDetailsService(customUserDetailsService);
        /** customUserDetailsService is expected to implement the UserDetailsService interface.
         * CustomUserDetailsService have the one  pre-defind method that is loadUserByUsername this method
         * return the userDetails Interface object .So we need to implement the interface to one class and
         * assign the value for that class attributes
         **/
        // Set the password encoder to NoOpPasswordEncoder (passwords are not encoded and are treated as plain text).
        // This is suitable for testing purposes, but should not be used in production due to security risks.
        authentication.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
        // To use a stronger encoding method, you can replace NoOpPasswordEncoder with other encoders like BCryptPasswordEncoder.

        // Return the fully configured AuthenticationProvider.
        return authentication;
    }

    /**
     * This method configures Cross-Origin Resource Sharing (CORS) for the application.
     * It allows web applications running on different origins to interact with the server.
     *
     * @return CorsConfigurationSource: A source that provides the CORS configuration for all endpoints.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource(){
        // Create a new instance of CorsConfiguration to define allowed cross-origin settings.
        CorsConfiguration corsConfiguration = new CorsConfiguration();

        // Set the allowed origins for CORS. In this case, only the "http://localhost:3000" origin is allowed.
        corsConfiguration.setAllowedOrigins(List.of("http://localhost:3000"));

        // Define the allowed HTTP methods (GET, POST, PUT, DELETE).
        corsConfiguration.setAllowedMethods(List.of("GET","POST","PUT","DELETE"));

        // Set the allowed headers for CORS requests. In this case, only "Content-Type" is allowed.
        corsConfiguration.setAllowedHeaders(List.of("Content-Type"));

        // Allows credentials (cookies, HTTP authentication, etc.) to be sent with the request.
        corsConfiguration.setAllowCredentials(true);

        // Create a new UrlBasedCorsConfigurationSource, which maps the configuration to specific URL patterns.
        UrlBasedCorsConfigurationSource urlBasedCorsConfigurationSource = new UrlBasedCorsConfigurationSource();

        // Register the CORS configuration for all URLs ("/**").
        urlBasedCorsConfigurationSource.registerCorsConfiguration("/**", corsConfiguration);

        // Return the configured CORS source.
        return urlBasedCorsConfigurationSource;
    }


    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        return (request, response, exception) -> {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            if(exception instanceof UsernameNotFoundException){
                response.getWriter().write("{\"error\": \"username is not found\"}");
            }else

             // Send 401 status on authentication failure
            response.getWriter().write("{\"error\": \"password wrong\"}");
        };
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();

    }


}
