package ir.bigz.spring.restSecuritySample.service;

import ir.bigz.spring.restSecuritySample.security.UserPermission;
import ir.bigz.spring.restSecuritySample.security.UserRole;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Component("UserPermissionServiceImpl")
public class UserPermissionServiceImpl implements UserPermissionService {

    private final RoleService roleService;

    @Autowired
    public UserPermissionServiceImpl(RoleService roleService) {
        this.roleService = roleService;
    }

    @Override
    @Transactional(propagation = Propagation.SUPPORTS, readOnly = true, rollbackFor = Exception.class)
    public Set<UserPermission> getUserPermissionForRole(String role) {

        Optional<UserRole> userRole = roleService.getUserRole(role);
        Set<UserPermission> userPermissionsForRole = new HashSet<>();

        if(userRole.isPresent()){
            userPermissionsForRole = userRole.get().getUserPermissionsForRole();
        }
        else{
            throw new IllegalStateException(String.format("role %s is not found",role));
        }
        return userPermissionsForRole;
    }
}
