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

    @Column(name = "email", nullable = false, unique = true)
    private String email;

    @Column(name = "authProvider")
    @Enumerated(EnumType.STRING)
    private AuthProvider authProvider;

    @Column(nullable = false)
    private Boolean emailVerified = false;

    @Column(name = "password")
    private String password;

    @Column(name = "active", nullable = false)
    private boolean active;


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

    public ApplicationUser(long id, String userName, String email, String password, boolean active) {
        this.id = id;
        this.userName = userName;
        this.email = email;
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

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public AuthProvider getAuthProvider() {
        return authProvider;
    }

    public void setAuthProvider(AuthProvider authProvider) {
        this.authProvider = authProvider;
    }

    public Boolean getEmailVerified() {
        return emailVerified;
    }

    public void setEmailVerified(Boolean emailVerified) {
        this.emailVerified = emailVerified;
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
