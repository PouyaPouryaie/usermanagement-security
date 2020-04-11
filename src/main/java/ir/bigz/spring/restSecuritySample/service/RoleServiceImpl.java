package ir.bigz.spring.restSecuritySample.service;

import ir.bigz.spring.restSecuritySample.dao.UserRoleDao;
import ir.bigz.spring.restSecuritySample.security.UserRole;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component("RoleServiceImpl")
public class RoleServiceImpl implements RoleService {

    private final UserRoleDao userRoleDao;

    @Autowired
    public RoleServiceImpl(@Qualifier("UserRoleDaoImpl") UserRoleDao userRoleDao) {
        this.userRoleDao = userRoleDao;
    }

    @Override
    public Optional<UserRole> getUserRole(String roleName) {
        return userRoleDao.getUserRole(roleName);
    }
}
