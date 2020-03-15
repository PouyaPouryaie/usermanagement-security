package ir.bigz.spring.restSecuritySample.security;

import ir.bigz.spring.restSecuritySample.dao.ApplicationUserDao;
import ir.bigz.spring.restSecuritySample.model.ApplicationUser;
import org.hibernate.Session;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.jpa.provider.HibernateUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class SecurityUserService implements UserDetailsService {

    private final ApplicationUserDao applicationUserDao;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public SecurityUserService(@Qualifier("applicationUserDaoImpl") ApplicationUserDao applicationUserDao,
                               PasswordEncoder passwordEncoder) {
        this.applicationUserDao = applicationUserDao;
        this.passwordEncoder = passwordEncoder;
    }


    @Override
    @Transactional(propagation = Propagation.SUPPORTS, readOnly = true, rollbackFor = Exception.class)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return getUserByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(
                        String.format("username %s not found.", username)
                ));
    }


    private Optional<SecurityUser> getUserByUsername(String username){

        Optional<ApplicationUser> applicationUserFromDao = applicationUserDao
                .selectApplicationUserByUserName(username);


//        Set<UserPermission> s1 = applicationUserFromDao.get().getUserPermissionsForUser();
//        for(UserPermission sss: s1){
//            System.out.println(sss.getPermissionName());
//        }

        Set<SimpleGrantedAuthority> simpleGrantedAuthorities = new HashSet<>();
        if(applicationUserFromDao.isPresent()){
            Set<SimpleGrantedAuthority> collectUserPermissionFromUser = applicationUserFromDao.get()
                    .getUserPermissionsForUser()
                    .stream()
                    .map(userPermission -> new SimpleGrantedAuthority(userPermission.getPermissionName()))
                    .collect(Collectors.toSet());

            Set<UserPermission> userPermissionsFromRole = applicationUserFromDao.get()
                    .getUserRoles()
                    .stream()
                    .map(userRole -> userRole.getUserPermissionsForRole())
                    .flatMap(Collection::stream)
                    .collect(Collectors.toSet());

            Set<SimpleGrantedAuthority> collectUserPermissionFromRole = userPermissionsFromRole
                    .stream()
                    .map(userPermission -> new SimpleGrantedAuthority(userPermission.getPermissionName()))
                    .collect(Collectors.toSet());

            simpleGrantedAuthorities.addAll(collectUserPermissionFromUser);
            simpleGrantedAuthorities.addAll(collectUserPermissionFromRole);

            Set<SimpleGrantedAuthority> collectRoleForUser = applicationUserFromDao.get().getUserRoles()
                    .stream()
                    .map(userRole -> userRole.getRoleName())
                    .map(s -> new SimpleGrantedAuthority(s))
                    .collect(Collectors.toSet());

            simpleGrantedAuthorities.addAll(collectRoleForUser);

        }

        SecurityUser securityUser = new SecurityUser(simpleGrantedAuthorities,
                applicationUserFromDao.get().getUserName(),
                passwordEncoder.encode(applicationUserFromDao.get().getPassword()),
                true,
                true,
                true,
                true);

        return Optional.ofNullable(securityUser);
    }
}
