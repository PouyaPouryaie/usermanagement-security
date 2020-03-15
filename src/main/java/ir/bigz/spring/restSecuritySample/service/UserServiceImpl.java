package ir.bigz.spring.restSecuritySample.service;

import com.google.common.collect.Lists;
import ir.bigz.spring.restSecuritySample.model.ApplicationUser;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service("sample")
public class UserServiceImpl implements UserService{


    private List<ApplicationUser> userListSample = Lists.newArrayList(
            new ApplicationUser(1,"pouya","pouya", true),
            new ApplicationUser(1,"ali","ali", true),
            new ApplicationUser(1,"atena","atena", true)
    );

    @Override
    public List<ApplicationUser> getAllUser() {
        return userListSample;
    }

    @Override
    public Optional<ApplicationUser> getUser(long userId) {
        return Optional.empty();
    }

    @Override
    public Optional<ApplicationUser> deleteUser(long userId) {
        return Optional.empty();
    }

    @Override
    public ApplicationUser updateUser(ApplicationUser user) {
        return null;
    }

    @Override
    public ApplicationUser createUser(ApplicationUser user) {
        return null;
    }
}
