package com.security.example.demo.Service;

import com.security.example.demo.Entity.CustomUserDetails;
import com.security.example.demo.Entity.User;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {


    AuthenticationManager authManager;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {


        System.out.println("username : "+username);
        if(!username.equals("hello"))
            throw new UsernameNotFoundException("Username is not found");


        return new CustomUserDetails(new User("hello","hello@123"));


    }



    public CustomUserDetails Authticated(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(authentication != null  && authentication.isAuthenticated()) {
            Object principal = authentication.getPrincipal();
            if (principal instanceof CustomUserDetails) {
                CustomUserDetails customUser = (CustomUserDetails) principal;
                return customUser;  // return your custom user details object
            }
        }
        return null;
    }


}
