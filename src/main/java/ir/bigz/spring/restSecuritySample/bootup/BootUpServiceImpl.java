package ir.bigz.spring.restSecuritySample.bootup;

import ir.bigz.spring.restSecuritySample.dao.UserPermissionDao;
import ir.bigz.spring.restSecuritySample.security.UserPermission;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

@Service
public class BootUpServiceImpl implements BootUpService{

    @Autowired
    private Environment env;

    @Autowired
    private UserPermissionDao userPermissionDao;

    @Override
    public List<String> getControllerUrl() {

        List<String> listOfMethod = new ArrayList<>();

        try {
            var classes = ControllerCrawlerService.getClasses(
                    Objects.requireNonNull(env.getProperty("application.controller.package.address")));


            for(Class c:classes){
                System.out.println(c.getName());
                Method[] methods = c.getDeclaredMethods();
                for(Method method: methods){
                    System.out.println(method.getName());
                    listOfMethod.add(method.getName());
                }
            }

            return listOfMethod;

        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }
}
