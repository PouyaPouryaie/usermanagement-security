package ir.bigz.spring.restSecuritySample.security;

import com.fasterxml.jackson.annotation.JsonIgnore;
import ir.bigz.spring.restSecuritySample.model.ApplicationUser;

import javax.persistence.*;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "role")
@Access(AccessType.FIELD)
public class UserRole {

    @Id
    @GeneratedValue
    @Column(name = "role_id")
    private long roleId;

    @Column(name = "role_name")
    private String roleName;

    @Column(name = "role_description")
    private String roleDescription;

    @ManyToMany(mappedBy = "userRoles")
    @JsonIgnore
    private Set<ApplicationUser> applicationUsers = new HashSet<>();

    @ManyToMany(cascade = { CascadeType.ALL })
    @JoinTable(
            name = "role_permission",
            joinColumns = { @JoinColumn(name = "role_id") },
            inverseJoinColumns = { @JoinColumn(name = "permission_id") }
    )
    private Set<UserPermission> userPermissionsForRole = new HashSet<>();

    public UserRole() {
    }

    public long getRoleId() {
        return roleId;
    }

    public void setRoleId(long roleId) {
        this.roleId = roleId;
    }

    public String getRoleName() {
        return roleName;
    }

    public void setRoleName(String roleName) {
        this.roleName = roleName;
    }

    public String getRoleDescription() {
        return roleDescription;
    }

    public void setRoleDescription(String roleDescription) {
        this.roleDescription = roleDescription;
    }

    public Set<ApplicationUser> getApplicationUsers() {
        return applicationUsers;
    }

    public void setApplicationUsers(Set<ApplicationUser> applicationUsers) {
        this.applicationUsers = applicationUsers;
    }

    public Set<UserPermission> getUserPermissionsForRole() {
        return userPermissionsForRole;
    }

    public void setUserPermissionsForRole(Set<UserPermission> userPermissionsForRole) {
        this.userPermissionsForRole = userPermissionsForRole;
    }
}
