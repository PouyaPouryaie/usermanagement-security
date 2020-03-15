package ir.bigz.spring.restSecuritySample.model;

import ir.bigz.spring.restSecuritySample.security.UserPermission;
import ir.bigz.spring.restSecuritySample.security.UserRole;

import javax.persistence.*;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "application_user")
@Access(AccessType.FIELD)
public class ApplicationUser {

    //serialize and deserialize
    static final long serialVersionUID=4L;

    @Id
    @GeneratedValue
    @Column(name = "user_id")
    private long id;

    @Column(name = "username", nullable = false, unique = true)
    private String userName;

    @Column(name = "password", nullable = false)
    private String password;

    @Column(name = "active", nullable = false)
    private boolean active;

/*    @ManyToMany
    @JoinTable(
            name = "application_user_role",
            joinColumns = @JoinColumn(
                    name = "user_id", referencedColumnName = "user_id"),
            inverseJoinColumns = @JoinColumn(
                    name = "role_id", referencedColumnName = "role_id"))
    private Collection<UserRole> roles;*/

    @ManyToMany(cascade = { CascadeType.ALL })
    @JoinTable(
            name = "application_user_role",
            joinColumns = { @JoinColumn(name = "user_id") },
            inverseJoinColumns = { @JoinColumn(name = "role_id") }
    )
    private Set<UserRole> userRoles = new HashSet<>();


    @ManyToMany(cascade = { CascadeType.ALL })
    @JoinTable(
            name = "application_user_permission",
            joinColumns = { @JoinColumn(name = "user_id") },
            inverseJoinColumns = { @JoinColumn(name = "permission_id") }
    )
    private Set<UserPermission> userPermissionsForUser = new HashSet<>();

    public ApplicationUser(){

    }

    public ApplicationUser(long id, String userName, String password, boolean active) {
        this.id = id;
        this.userName = userName;
        this.password = password;
        this.active = active;
    }


    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public Set<UserRole> getUserRoles() {
        return userRoles;
    }

    public void setUserRoles(Set<UserRole> userRoles) {
        this.userRoles = userRoles;
    }


    public Set<UserPermission> getUserPermissionsForUser() {
        return userPermissionsForUser;
    }

    public void setUserPermissionsForUser(Set<UserPermission> userPermissionsForUser) {
        this.userPermissionsForUser = userPermissionsForUser;
    }

    @Override
    public String toString() {
        return "ApplicationUser{" +
                "id=" + id +
                ", userName='" + userName + '\'' +
                ", password='" + password + '\'' +
                ", active=" + active +
                '}';
    }
}
