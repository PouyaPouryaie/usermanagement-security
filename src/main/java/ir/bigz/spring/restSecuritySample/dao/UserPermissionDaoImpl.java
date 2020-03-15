package ir.bigz.spring.restSecuritySample.dao;

import ir.bigz.spring.restSecuritySample.model.ApplicationUser;
import ir.bigz.spring.restSecuritySample.security.UserPermission;
import org.springframework.stereotype.Component;

@Component("UserPermissionDaoImpl")
public class UserPermissionDaoImpl extends DaoRepositoryImpl<UserPermission, Long> implements UserPermissionDao {
}
