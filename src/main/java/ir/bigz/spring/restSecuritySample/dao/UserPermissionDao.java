package ir.bigz.spring.restSecuritySample.dao;

import ir.bigz.spring.restSecuritySample.model.ApplicationUser;
import ir.bigz.spring.restSecuritySample.security.UserPermission;
import org.springframework.stereotype.Repository;

@Repository
public interface UserPermissionDao extends DaoRepository<UserPermission,Long> {
}
