package ir.bigz.spring.restSecuritySample.service;

import ir.bigz.spring.restSecuritySample.security.UserPermission;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
public interface UserPermissionService {

    Set<UserPermission> getUserPermissionForRole(String role);
}
