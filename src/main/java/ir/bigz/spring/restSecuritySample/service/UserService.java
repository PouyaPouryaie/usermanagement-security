package ir.bigz.spring.restSecuritySample.service;

import ir.bigz.spring.restSecuritySample.model.ApplicationUser;

import java.util.List;
import java.util.Optional;


public interface UserService {

    public List<ApplicationUser> getAllUser();
    public Optional<ApplicationUser> getUser(long userId);
    public Optional<ApplicationUser> deleteUser(long userId);
    public ApplicationUser updateUser(ApplicationUser user);
    public ApplicationUser createUser(ApplicationUser user);
}
