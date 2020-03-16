package ir.bigz.spring.restSecuritySample.controller;

import ir.bigz.spring.restSecuritySample.model.ApplicationUser;
import ir.bigz.spring.restSecuritySample.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/sample")
public class SampleController {

    private final UserService userService;

    @Autowired
    public SampleController(@Qualifier("sample") UserService userService) {
        this.userService = userService;
    }

    @PostMapping(path = "createSample")
    public void createSample(@RequestBody ApplicationUser user){
        System.out.println("createSample");
        userService.createUser(user);
    }

    @PutMapping(path = "updateSample")
    public void updateSample(@RequestBody ApplicationUser user){
        System.out.println("updateSample");
        userService.updateUser(user);
    }

    @DeleteMapping(path = "deleteSample/{userId}")
    public void deleteSample(@PathVariable("userId") long userId){
        System.out.println("deleteSample");
        userService.deleteUser(userId);
    }

    @GetMapping(path = "getSample/{userId}")
    public void getSample(@PathVariable("userId") long userId){
        System.out.println("getSample");
        userService.getUser(userId);
    }

    @GetMapping(path = "getAllSample")
    public void getAllSample(){
        System.out.println("getAllSample");
        userService.getAllUser();
    }
}
