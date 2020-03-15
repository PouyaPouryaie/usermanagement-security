package ir.bigz.spring.restSecuritySample.dao;

import ir.bigz.spring.restSecuritySample.model.ApplicationUser;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Component("applicationUserDaoImpl")
public class ApplicationUserDaoImpl extends DaoRepositoryImpl<ApplicationUser, Long> implements ApplicationUserDao {

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUserName(String username) {

        Optional<ApplicationUser> applicationUser = Optional.empty();
        List<ApplicationUser> resultList = new ArrayList<>();
        String query = "select u from ApplicationUser u where u.userName= '" + username + "'";

        try {
            resultList = genericSearch(query);
            if(resultList.get(0)!= null){
                applicationUser = Optional.ofNullable(resultList.get(0));
            }
        }catch (Exception e){
            System.out.println(e.getMessage());
        }

        return applicationUser;
    }
}
