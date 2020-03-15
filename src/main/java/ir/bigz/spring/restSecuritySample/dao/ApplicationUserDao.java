package ir.bigz.spring.restSecuritySample.dao;

import ir.bigz.spring.restSecuritySample.model.ApplicationUser;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ApplicationUserDao extends DaoRepository<ApplicationUser,Long> {

    Optional<ApplicationUser> selectApplicationUserByUserName(String username);
}
