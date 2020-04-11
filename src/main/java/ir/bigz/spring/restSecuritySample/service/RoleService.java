package ir.bigz.spring.restSecuritySample.service;

import ir.bigz.spring.restSecuritySample.security.UserRole;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public interface RoleService {

    Optional<UserRole> getUserRole(String roleName);
}
