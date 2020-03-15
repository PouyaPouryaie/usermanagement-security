package ir.bigz.spring.restSecuritySample.dao;

import ir.bigz.spring.restSecuritySample.model.ApplicationUser;
import ir.bigz.spring.restSecuritySample.security.UserRole;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Component("UserRoleDaoImpl")
public class UserRoleDaoImpl extends DaoRepositoryImpl<UserRole, Long> implements UserRoleDao {

    @Override
    public Optional<UserRole> getUserRole(String roleName) {

        Optional<UserRole> userRole = Optional.empty();
        List<UserRole> resultList = new ArrayList<>();

        String query = "select r from UserRole r join fetch r.userPermissionsForRole where r.roleName = 'ROLE_" + roleName + "'";

        try {
            resultList = genericSearch(query);
            userRole = Optional.ofNullable(resultList.get(0));
        }catch (Exception e){
            System.out.println(e.getMessage());
        }

        return userRole;
    }
}
