package ir.bigz.spring.restSecuritySample.filter;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class AuthorizeFilterConfig {

    @Value("#{'${application.permit.url}'.split(',')}")
    private List<String> filterList;

    public AuthorizeFilterConfig() {
    }

    public List<String> getFilterList() {
        return filterList;
    }
}
