package com.shopme.admin;

import com.shopme.admin.dao.UserRepo;
import com.shopme.admin.entity.Role;
import com.shopme.admin.entity.Roles;
import com.shopme.admin.entity.User;
import com.shopme.admin.service.RoleService;
import com.shopme.admin.service.UserService;
import com.shopme.admin.utils.Log;
import org.assertj.core.api.Assertions;
import org.jboss.aerogear.security.otp.api.Base32;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.Resource;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.context.ActiveProfiles;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@SpringBootTest
@Rollback(value = false)
@ActiveProfiles("test")
public class UserServiceTest {

    @Autowired UserRepo userRepo;

    @Autowired UserService userService;

    @Autowired RoleService roleService;

    @Autowired UserDetailsService userDetailsService;

    @Test public void shouldReturnAtLeastOneUser() {
        String keyword = "@gmai";

        List<User> users = userService.search(keyword);

        users.forEach(System.out::println);

        Assertions.assertThat(users).size().isGreaterThan(0);
    }

    @Test public void shouldReturnPagesAndElementsGreaterThanZero() {
        String keyword = "gmail";

        Page<User> page = userService.findPageByKeyword(keyword, 1);

        page.getContent().forEach(System.out::println);

        System.out.println(page.getTotalPages());
        System.out.println(page.getTotalElements());

        Assertions.assertThat(page.getTotalPages()).isGreaterThan(0);
        Assertions.assertThat(page.getTotalElements()).isGreaterThan(0);
    }

    @Test public void resourceShouldExist() throws IOException {
        String filename = "default.png";

        Resource resource = userService.getResource(filename);

        Assertions.assertThat(resource.exists()).isTrue();
    }

    @Test public void testSaveUser() throws IOException {
        String email = "newuser@gmail.com";
        String fname = "Firstname";
        String lname = "Lastname";
        String filename = "";
        String pass = email;

        User newUser = new User().email(email).enabled(1).firstName(fname).lastName(lname).filename(filename)
                .password(pass).use2FA().secret(Base32.random());

        userService.saveUser(newUser, new ArrayList<>(Arrays.asList(1, 0)), roleService.getRolesIds(), null,
                false);
    }

    @Test public void givenEmailShouldReturnUser() {
        String givenEmail = "darylldagondon@gmail.com";

        User user = userRepo.findByEmail(givenEmail);

        Assertions.assertThat(user.getEmail()).isEqualTo(givenEmail);
    }

    @Test public void givenIdUserMustBePresent() {
        int id = 4;

        Assertions.assertThat(userRepo.findById(id)).isPresent();
    }

    @Test public void shouldDeleteUserById() {
        int id = 3;

        userRepo.deleteById(id);

        Assertions.assertThat(userRepo.findById(id).isPresent()).isFalse();
    }

    @Test public void shouldEnableUser() {
        int id = 1;

        User user = userService.findById(id);
        user.enable();
        user.setPassword("rootuser4567");
        userService.saveUser(user);

        Assertions.assertThat(1).isEqualTo(userService.findById(id).getEnabled());
    }

    @Test public void shouldDisableUser() {
        int id = 1;

        User user = userService.findById(id);
        user.disable();
        user.setPassword("rootuser4567");
        userService.saveUser(user);

        Assertions.assertThat(0).isEqualTo(userService.findById(id).getEnabled());
    }

    @Test public void shouldReturnUserByEmailKeyword() {
        String email = "@gmail";

        List<User> results = userService.findByEmailLike(email);

        Assertions.assertThat(results).size().isGreaterThan(0);
    }

    @Test public void shouldReturnUserByLastnameKeyword() {
        String lastname = "User 1";

        List<User> results = userService.findByLastnameLike(lastname);

        Assertions.assertThat(results).size().isGreaterThan(0);
    }

    @Test public void shouldReturnUserByFirstnameKeyword() {
        String firstname = "User 1";

        List<User> results = userService.findByFirstnameLike(firstname);

        Assertions.assertThat(results).size().isGreaterThan(0);
    }

    @Test public void shouldReturnPageSizeGreaterThanZero() {
        Page<User> userPage = userService.findPage(1);

        Assertions.assertThat(userPage).size().isGreaterThan(0);
    }

    @Test public void shouldReturnAllUsers() {
        List<User> users = userService.findAll();

        Assertions.assertThat(users).size().isGreaterThan(0);
    }

    @Test public void shouldReturnSortedUsersByDirection() {
        String direction = "desc";
        //String direction = "asc";

        Page<User> sortedUsers = userService.getPageAndSort("firstName", direction, 3);

        sortedUsers.getContent().forEach(user -> System.out.println(user.getFirstName()+","+user.getLastName()));

        Assertions.assertThat(sortedUsers).size().isGreaterThan(0);
    }

    @Test public void userDetailsShouldNotBeNullGivenUsername() {
        String username = "newuser@gmail.com";

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        Assertions.assertThat(userDetails).isNotNull();
    }

    @Test public void emailShouldExist() {
        String email = "newuser1@gmail.com";
        Assertions.assertThat(userService.isDuplicate(email)).isTrue();
    }

    @Test public void emailShouldBelongToUserId() {
        String email = "newuser1@gmail.com";
        int id = 601;

        Assertions.assertThat(userService.ownerOwnedEmail(email, id)).isTrue();
    }

    @Test public void roleShouldBeAddedToUser() {
        String email = "rodrigoduterte@gmail.com";
        String role = Roles.Salesperson.name();

        org.junit.jupiter.api.Assertions.assertNotNull(userService.findByEmail(email));

        userService.addRoleToUser(email, role);

        User user = userService.findByEmail(email);
        Role checkRole = roleService.findOne(2);

        Set<String> set = user.getRoles().stream().map(Role::getName).collect(Collectors.toSet());

        Assertions.assertThat(set).contains(checkRole.getName());
    }

    @Test public void testModifyListByIdAsc() {
        ArrayList<User> users = userService.sortList(
                new ArrayList<>(userService.findAll()), "id", "asc");
        List<Integer> sortedList = users.stream().map(user -> user.getId()).collect(Collectors.toList());
        Assertions.assertThat(sortedList.stream().sorted().collect(Collectors.toList())).isEqualTo(sortedList);
    }

    @Test public void testModifyListByIdDesc() {
        ArrayList<User> users = userService.sortList(
                new ArrayList<>(userService.findAll()), "id", "desc");
        List<Integer> sortedList = users.stream().map(user -> user.getId()).collect(Collectors.toList());
        Assertions.assertThat(sortedList.stream().sorted(Comparator.reverseOrder()).collect(Collectors.toList()))
                .isEqualTo(sortedList);
    }

    @Test public void testModifyListByEmailAsc() {
        ArrayList<User> users = userService.sortList(
                new ArrayList<>(userService.findAll()), "email", "asc");
        List<String> sortedList = users.stream().map(user -> user.getEmail()).collect(Collectors.toList());
        Assertions.assertThat(sortedList.stream().sorted().collect(Collectors.toList())).isEqualTo(sortedList);
    }

    @Test public void testModifyListByEmailDesc() {
        ArrayList<User> users = userService.sortList(
                new ArrayList<>(userService.findAll()), "email", "desc");
        List<String> sortedList = users.stream().map(user -> user.getEmail()).collect(Collectors.toList());
        Assertions.assertThat(sortedList.stream().sorted(Comparator.reverseOrder()).collect(Collectors.toList()))
                .isEqualTo(sortedList);
    }

    @Test public void testModifyListByFirstnameAsc() {
        ArrayList<User> users = userService.sortList(
                new ArrayList<>(userService.findAll()), "firstName", "asc");
        List<String> sortedList = users.stream().map(user -> user.getFirstName()).collect(Collectors.toList());
        Assertions.assertThat(sortedList.stream().sorted().collect(Collectors.toList())).isEqualTo(sortedList);
    }

    @Test public void testModifyListByFirstnameDesc() {
        ArrayList<User> users = userService.sortList(
                new ArrayList<>(userService.findAll()), "firstName", "desc");
        List<String> sortedList = users.stream().map(user -> user.getFirstName()).collect(Collectors.toList());
        Assertions.assertThat(sortedList.stream().sorted(Comparator.reverseOrder()).collect(Collectors.toList()))
                .isEqualTo(sortedList);
    }

    @Test public void testModifyListByLastnameAsc() {
        ArrayList<User> users = userService.sortList(
                new ArrayList<>(userService.findAll()), "lastName", "asc");
        List<String> sortedList = users.stream().map(user -> user.getFirstName()).collect(Collectors.toList());
        Assertions.assertThat(sortedList.stream().sorted().collect(Collectors.toList())).isEqualTo(sortedList);
    }

    @Test public void testModifyListByLastnameDesc() {
        ArrayList<User> users = userService.sortList(
                new ArrayList<>(userService.findAll()), "lastName", "desc");
        List<String> sortedList = users.stream().map(user -> user.getFirstName()).collect(Collectors.toList());
        Assertions.assertThat(sortedList.stream().sorted(Comparator.reverseOrder()).collect(Collectors.toList()))
                .isEqualTo(sortedList);
    }

    @Test public void shouldSaveUser() {
        String newEmail = "superuser@gmail.com";

        User root = new User()
                .email(newEmail)
                .enabled(1)
                .firstName("Super")
                .lastName("User")
                .filename(null)
                .password(newEmail)
                .use2FA()
                .secret(Base32.random());

        userService.saveUser(root);

        userService.addRoleToUser(newEmail, Roles.Admin.name());

        User user = userService.findByEmail(newEmail);

        Assertions.assertThat(newEmail).isEqualTo(user.getEmail());
    }

    @Test public void shouldDeleteAllUsers() {
        userService.deleteAll();

        Assertions.assertThat(userService.findAll()).size().isLessThan(1);
    }

    @Test public void shouldAddManyUsers() {

        ArrayList<Integer> roles = roleService.getRolesIds();
        ArrayList<Integer> enabled = new ArrayList<>(Arrays.asList(1, 0));

        IntStream.range(1, 150).forEach(number -> {
            User newUser = new User()
                    .email("newuser"+number+"@gmail.com")
                    .enabled(1)
                    .firstName("User "+number)
                    .lastName("User "+number)
                    .filename(null)
                    .password("newuser"+number+"@gmail.com")
                    .use2FA()
                    .secret(Base32.random());

            try {
                userService.saveUser(newUser, enabled, roles, null, false);
            } catch (IOException e) {Log.error(e.toString());}
        });

        Assertions.assertThat(userService.findAll()).size().isGreaterThan(0);
    }

    @Test public void shouldDeleteAllUsersAndRoles() {
        userService.deleteAll();
        Assertions.assertThat(userService.findAll()).size().isLessThan(1);

        roleService.deleteAll();
        Assertions.assertThat(roleService.findAll()).size().isLessThan(1);
    }
}