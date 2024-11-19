package com.security.example.demo.Controller;

import com.security.example.demo.Entity.User;
import com.security.example.demo.Service.CustomUserDetailsService;
import com.security.example.demo.Service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
public class UserController {

    @Autowired
    CustomUserDetailsService service;

    @Autowired
    UserService userService;

    @GetMapping("/auth/login")
    public  String login()
    {
        String username="no name beacause it null";
        if(service.Authticated() != null)
            username = service.Authticated().getUsername();
        System.out.println(username);

        System.out.println("In the before login");
        return "login";
    }



    @ResponseBody
    @PostMapping("/auth/login")
    public ResponseEntity<?> login(HttpServletRequest request,@RequestParam String username , @RequestParam String password ) {


            System.out.println("User" + username);
            Authentication authentication =userService.verify(new User(username,password), request);
            if(authentication.isAuthenticated()) {
                System.out.println("Is authenticated");
                return new ResponseEntity<>("Login SuccessFull", HttpStatus.OK); // Redirect to a secured page
            }
            return new ResponseEntity<>("Login Failed", HttpStatus.UNAUTHORIZED);
    }

    @GetMapping("/csrf")
    @ResponseBody
    public CsrfToken csrfToken(HttpServletRequest request) {
        // Retrieve CSRF token from the request attribute
        CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        if (csrfToken != null) {
            return csrfToken;
        }
        return  null;
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

    @GetMapping("/session")
    public String sessionInfo(HttpSession session) {
        return "Session ID: " + session.getId();
    }
}
