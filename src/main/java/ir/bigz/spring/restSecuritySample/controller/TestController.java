package ir.bigz.spring.restSecuritySample.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/oauth")
public class TestController {

    @RequestMapping("/home")
    public String home(){
        return "home";
    }

    @GetMapping("/custom-login")
    public String loadLoginPage(){
        return "login";
    }
}
