package com.security.example.demo.Controller;

import com.security.example.demo.Entity.User;
import com.security.example.demo.Service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

//@RestController
public class userRestController {

    @Autowired
    CustomUserDetailsService userDetailsService;

        @PostMapping("/login")
        public ResponseEntity loginFunction(@RequestBody User user) {
            System.out.println("In the rest controller");
           return  new ResponseEntity<>("sucessfull",HttpStatus.OK);
        }


}
