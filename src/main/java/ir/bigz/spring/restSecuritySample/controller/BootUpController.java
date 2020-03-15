package ir.bigz.spring.restSecuritySample.controller;

import ir.bigz.spring.restSecuritySample.bootup.BootUpService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("bootup/api/sample")
public class BootUpController {

    private final BootUpService bootUpService;

    @Autowired
    public BootUpController(BootUpService bootUpService) {
        this.bootUpService = bootUpService;
    }

    @GetMapping(path = "getApiEndpoint", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<String> getApiEndpoint(){
        return bootUpService.getControllerUrl();
    }

}
