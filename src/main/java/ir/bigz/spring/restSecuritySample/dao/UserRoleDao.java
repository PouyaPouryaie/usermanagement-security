package ir.bigz.spring.restSecuritySample.dao;

import ir.bigz.spring.restSecuritySample.model.ApplicationUser;
import ir.bigz.spring.restSecuritySample.security.UserRole;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRoleDao extends DaoRepository<UserRole,Long> {

    Optional<UserRole> getUserRole(String roleName);
}
