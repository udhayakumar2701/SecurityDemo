package com.security.example.demo.Controller;

import com.security.example.demo.Entity.CustomUserDetails;
import com.security.example.demo.Entity.User;
import com.security.example.demo.Service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@Controller
public class UserController {

    @Autowired
    CustomUserDetailsService service;

    @GetMapping("/login")
    public  String login()
    {
        System.out.println("In the before login");
        return "login";
    }



    @GetMapping("/home")
    public String AfterLogin()
    {
        String username="no name beacause it null";
        if(service.Authticated() != null)
         username = service.Authticated().getUsername();
        System.out.println(username);
        return "Home";
    }


}
