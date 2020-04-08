package ir.bigz.spring.restSecuritySample.service;

import com.google.common.collect.Lists;
import ir.bigz.spring.restSecuritySample.dao.ApplicationUserDao;
import ir.bigz.spring.restSecuritySample.dao.UserRoleDao;
import ir.bigz.spring.restSecuritySample.model.ApplicationUser;
import ir.bigz.spring.restSecuritySample.security.UserRole;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Component("UserServiceImpl")
public class UserServiceImpl implements UserService{

    private final ApplicationUserDao applicationUserDao;
    private final UserRoleDao userRoleDao;


    private List<ApplicationUser> userListSample = Lists.newArrayList(
            new ApplicationUser(1,"pouya","pouya@email.com","pouya", true),
            new ApplicationUser(1,"ali","ali@email.com","ali", true),
            new ApplicationUser(1,"atena","atena@email.com","atena", true)
    );

    @Autowired
    public UserServiceImpl(ApplicationUserDao applicationUserDao, UserRoleDao userRoleDao) {
        this.applicationUserDao = applicationUserDao;
        this.userRoleDao = userRoleDao;
    }

    @Override
    public List<ApplicationUser> getAllUser() {
        return userListSample;
    }

    @Override
    public Optional<ApplicationUser> getUserById(long userId) {
        return Optional.empty();
    }

    @Override
    public Optional<ApplicationUser> getUserByEmail(String email) {
        return applicationUserDao.selectApplicationUserByEmail(email);
    }

    @Override
    public Optional<ApplicationUser> getUserByUserName(String userName) {
        return applicationUserDao.selectApplicationUserByUserName(userName);
    }

    @Override
    public Optional<ApplicationUser> deleteUser(long userId) {
        return Optional.empty();
    }

    @Override
    public ApplicationUser updateUser(ApplicationUser user) {
        return applicationUserDao.update(user);
    }

    @Override
    @Transactional(propagation = Propagation.SUPPORTS, readOnly = true, rollbackFor = Exception.class)
    public ApplicationUser createUser(ApplicationUser user) {
        ApplicationUser applicationUser = applicationUserDao.insert(user);
        if(applicationUser.getId() != 0){
            Optional<UserRole> userRoleOptional = userRoleDao.getUserRole("USER");
            if(userRoleOptional.isPresent()){
                Set<UserRole> userRoles = new HashSet<>();
                userRoles.add(userRoleOptional.get());
                applicationUser.setUserRoles(userRoles);
                applicationUserDao.update(applicationUser);
            }
            else{
                throw new IllegalStateException("user role not found");
            }
        }
        else{
            throw new IllegalStateException("user not created.");
        }
        return applicationUser;
    }
}
