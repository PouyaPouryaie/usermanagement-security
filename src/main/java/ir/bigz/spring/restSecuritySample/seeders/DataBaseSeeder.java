package ir.bigz.spring.restSecuritySample.seeders;

import ir.bigz.spring.restSecuritySample.bootup.BootUpService;
import ir.bigz.spring.restSecuritySample.dao.ApplicationUserDao;
import ir.bigz.spring.restSecuritySample.dao.UserPermissionDao;
import ir.bigz.spring.restSecuritySample.dao.UserRoleDao;
import ir.bigz.spring.restSecuritySample.model.ApplicationUser;
import ir.bigz.spring.restSecuritySample.security.UserPermission;
import ir.bigz.spring.restSecuritySample.security.UserRole;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

@Component
public class DataBaseSeeder {

    private ApplicationUserDao applicationUserDao;
    private UserPermissionDao userPermissionDao;
    private UserRoleDao userRoleDao;
    private BootUpService bootUpService;

    @Autowired
    public DataBaseSeeder(ApplicationUserDao applicationUserDao,
                          UserPermissionDao userPermissionDao,
                          UserRoleDao userRoleDao,
                          BootUpService bootUpService) {
        this.applicationUserDao = applicationUserDao;
        this.userPermissionDao = userPermissionDao;
        this.userRoleDao = userRoleDao;
        this.bootUpService = bootUpService;
    }

    @EventListener
    public void seed(ContextRefreshedEvent event){
        initBasicPermission();
        initBasicRole();
        initBasicUser();
    }


    public void initBasicUser(){

        Optional<ApplicationUser> adminFindByName = applicationUserDao.selectApplicationUserByUserName("admin");
        Optional<UserRole> adminRoleFromDb = userRoleDao.getUserRole("Admin");
        ApplicationUser applicationUser = new ApplicationUser();

        if (adminFindByName.isEmpty()) {
            applicationUser.setActive(true);
            applicationUser.setPassword("password");
            applicationUser.setUserName("admin");
            applicationUser.setEmail("admin@admin.com");
            applicationUserDao.insert(applicationUser);
            if(adminRoleFromDb.isPresent()){
                Set<UserRole> userRoles = new HashSet<>();
                userRoles.add(adminRoleFromDb.get());
                applicationUser.setUserRoles(userRoles);
                applicationUserDao.update(applicationUser);
            }
        }
    }


    public void initBasicRole(){
        Optional<UserRole> userRoleFindByRole = userRoleDao.getUserRole("Admin");
        UserRole adminRole = new UserRole();

        if(userRoleFindByRole.isPresent()){
            adminRole = userRoleFindByRole.get();
            Set<UserPermission> userPermissionForRole = adminRole.getUserPermissionsForRole();
            List<UserPermission> userPermissionFromUserPermissionTable = userPermissionDao.getAll();

/*            Map<String, UserPermission> userPermissionFromDbMap = userPermissionForRole.stream()
                    .collect(Collectors.toMap(
                            UserPermission::getPermissionName,
                            userPermission -> userPermission
                    ));*/

            Map<String, UserPermission> userPermissionFromDbMap = new HashMap<>();
            for(UserPermission userPermission : userPermissionForRole){
                userPermissionFromDbMap.put(userPermission.getPermissionName(), userPermission);
            }

            Set<UserPermission> userPermissionSets = userPermissionFromUserPermissionTable.stream()
                    .filter(u -> userPermissionFromDbMap.get(u.getPermissionName()) == null)
                    .collect(Collectors.toSet());

            if(userPermissionSets.size() > 0){
                userPermissionForRole.addAll(userPermissionSets);

                adminRole.setUserPermissionsForRole(userPermissionForRole);

                userRoleDao.update(adminRole);
            }

        }else{
            adminRole.setRoleName("ROLE_Admin");
            adminRole.setRoleDescription("role with all privilege");
            userRoleDao.insert(adminRole);
            List<UserPermission> userPermissionFromUserPermissionTable = userPermissionDao.getAll();
            adminRole.setUserPermissionsForRole(new HashSet<>(userPermissionFromUserPermissionTable));
            userRoleDao.update(adminRole);
        }

/*        UserRole userRole = new UserRole();
        userRole.setRoleName("ROLE_USER");
        userRole.setRoleDescription("role for normal user");
        userRoleDao.insert(userRole);
        List<UserPermission> userPermissionFromUserPermissionTable = userPermissionDao.getAll();
        Set<UserPermission> getAllSample = userPermissionFromUserPermissionTable.stream()
                .filter(userPermission -> userPermission.getPermissionName().equals("getAllSample"))
                .collect(Collectors.toSet());
        userRole.setUserPermissionsForRole(new HashSet<>(getAllSample));
        userRoleDao.update(userRole);*/
    }

    public void initBasicPermission(){
        List<String> listOfMethod = bootUpService.getControllerUrl();
        List<UserPermission> userPermissions = userPermissionDao.getAll();

        Map<String, UserPermission> userPermissionMap = new HashMap<>();
        for(UserPermission userPermission : userPermissions){
            userPermissionMap.put(userPermission.getPermissionName(), userPermission);
        }

/*        Map<String, UserPermission> userPermissionFromDbMap = userPermissions.stream().collect(
                Collectors.toMap(UserPermission::getPermissionName, userPermission -> userPermission));*/


        listOfMethod.stream()
                .filter(s -> userPermissionMap.get(s) == null)
                .forEach(s -> userPermissionDao.insert(new UserPermission(s)));
    }
}
