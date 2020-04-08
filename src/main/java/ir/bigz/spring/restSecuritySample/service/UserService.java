package ir.bigz.spring.restSecuritySample.service;

import ir.bigz.spring.restSecuritySample.model.ApplicationUser;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;


@Service
public interface UserService {

    public List<ApplicationUser> getAllUser();
    public Optional<ApplicationUser> getUserById(long userId);
    public Optional<ApplicationUser> getUserByEmail(String email);
    public Optional<ApplicationUser> getUserByUserName(String userName);
    public Optional<ApplicationUser> deleteUser(long userId);
    public ApplicationUser updateUser(ApplicationUser user);
    public ApplicationUser createUser(ApplicationUser user);
}
