package ir.bigz.spring.restSecuritySample.security;

import com.fasterxml.jackson.annotation.JsonIgnore;
import ir.bigz.spring.restSecuritySample.model.ApplicationUser;

import javax.persistence.*;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "permission")
@Access(AccessType.FIELD)
public class UserPermission {

    @Id
    @GeneratedValue
    @Column(name = "permission_id")
    private long permissionId;

    @Column(name = "permission_name")
    private String permissionName;

    @ManyToMany(mappedBy = "userPermissionsForUser")
    @JsonIgnore
    private Set<ApplicationUser> applicationUsers = new HashSet<>();

    @ManyToMany(mappedBy = "userPermissionsForRole")
    @JsonIgnore
    private Set<UserRole> roles = new HashSet<>();

    public UserPermission() {
    }

    public UserPermission(String permissionName) {
        this.permissionName = permissionName;
    }

    public long getPermissionId() {
        return permissionId;
    }

    public void setPermissionId(long permissionId) {
        this.permissionId = permissionId;
    }

    public String getPermissionName() {
        return permissionName;
    }

    public void setPermissionName(String permissionName) {
        this.permissionName = permissionName;
    }

    public Set<ApplicationUser> getApplicationUsers() {
        return applicationUsers;
    }

    public void setApplicationUsers(Set<ApplicationUser> applicationUsers) {
        this.applicationUsers = applicationUsers;
    }

    public Set<UserRole> getRoles() {
        return roles;
    }

    public void setRoles(Set<UserRole> roles) {
        this.roles = roles;
    }
}
