package com.shopme.admin.controller;

import com.shopme.admin.config.ShopmeBackendSecurityConfig;
import com.shopme.admin.entity.Role;
import com.shopme.admin.entity.Roles;
import com.shopme.admin.entity.User;
import com.shopme.admin.service.RoleService;
import com.shopme.admin.service.UserService;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

@WebMvcTest
@ContextConfiguration(classes = {UserController.class, ShopmeBackendSecurityConfig.class, UserRestController.class})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Rollback(value = false)
@ActiveProfiles("test")
public class UserControllerTest {

    @Autowired WebApplicationContext context;

    @Autowired private MockMvc mockMvc;

    @MockBean private UserService userService;

    @MockBean private RoleService roleService;

    @MockBean BCryptPasswordEncoder bCryptPasswordEncoder;

    @MockBean private UserDetailsService userDetailsService;

    @Test
    public void testRoot() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders
                .get("/")
                .with(csrf()))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "newuser1@gmail.com", authorities = {"Admin"})
    public void testUsersRoot() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders
                        .get("/Users")
                        .with(csrf()))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "newuser1@gmail.com", authorities = {"Admin"})
    public void testUsersPage() throws Exception {
        int page = 2;

        mockMvc.perform(MockMvcRequestBuilders
                        .get("/Users/"+page)
                        .with(csrf()))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "newuser1@gmail.com", authorities = {"Admin"})
    public void testUsersPageWithDirection() throws Exception {
        int page = 2;

        mockMvc.perform(MockMvcRequestBuilders
                        .get("/Users/"+page+"/id")
                        .with(csrf()))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "newuser1@gmail.com", authorities = {"Admin"})
    public void testLoadAddUserForm() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders
                        .get("/AddUserForm")
                        .with(csrf()))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "newuser1@gmail.com", authorities = {"Admin"})
    public void testLoadUpdateUserForm() throws Exception {
        int userId = 5;

        User user = new User().id(5).email("newuser5@gmail.com").enabled(0)
                .firstName("User Firstname 5").lastName("User Lastname 5");

        Mockito.when(userService.findById(userId)).thenReturn(user);

        mockMvc.perform(MockMvcRequestBuilders
                        .get("/UpdateUserForm")
                        .param("userId", String.valueOf(userId))
                        .param("page", String.valueOf(1))
                        .with(csrf()))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "newuser1@gmail.com", authorities = {"Admin"})
    public void testEnable() throws Exception {
        int userid = 1;
        int page = 1;

        MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders
                .get("/Enable")
                .param("userid", String.valueOf(userid))
                .param("page", String.valueOf(page)))
                .andExpect(status().isOk())
                .andReturn();

        String msg = Objects.requireNonNull(mvcResult.getModelAndView()).getModel().get("alertMessage").toString();

        Assertions.assertThat(msg).isEqualTo("UserID "+userid+" has been enabled.");
    }

    @Test
    @WithMockUser(username = "newuser1@gmail.com", authorities = {"Admin"})
    public void testDisable() throws Exception {
        int userid = 1;
        int page = 1;

        MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders
                .get("/Disable")
                .param("userid", String.valueOf(userid))
                .param("page", String.valueOf(page))
                .with(csrf()))
                .andExpect(status().isOk())
                .andReturn();

        String msg = Objects.requireNonNull(mvcResult.getModelAndView()).getModel().get("alertMessage").toString();

        Assertions.assertThat(msg).isEqualTo("UserID "+userid+" has been disabled.");
    }

    @Test
    @WithMockUser(username = "newuser1@gmail.com", authorities = {"Admin"})
    public void testDelete() throws Exception {
        int userId = 1;

        MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders
                        .get("/DeleteUser")
                        .param("userId", String.valueOf(userId))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andReturn();

        String msg = Objects.requireNonNull(mvcResult.getModelAndView()).getModel().get("alertMessage").toString();

        Assertions.assertThat(msg).isEqualTo("UserId "+userId+" has been deleted.");
    }

    @Test
    @WithMockUser(username = "newuser1@gmail.com", authorities = {"Admin"})
    public void testSaveUser() throws Exception {

        User user = new User().enabled(1).id(1).email("dagondondaryll@gmail.com").password("dagondondaryll@gmail.com")
                .firstName("Daryll").lastName("Dagondon").filename("");

        MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders
                        .multipart("/SaveUser")
                        .file("photo", new byte[]{1,2,3})
                        .flashAttr("user", user)
                        .param("roles", "11")
                        .param("roles", "15")
                        .param("enabled", "1")
                        .param("enabled", "0")
                        .param("isUpdate", "false")
                        .param("page", "0")
                        .with(csrf()))
                .andExpect(status().isOk())
                .andReturn();

        Object object = Objects.requireNonNull(mvcResult.getModelAndView()).getModel().get("alertMessage");

        Assertions.assertThat(object).isNotNull();
    }

    @Test
    @WithMockUser(username = "newuser1@gmail.com", authorities = {"Admin"})
    public void testDeleteThenSearch() throws Exception {
        int userId = 1;
        int page = 1;
        String keyword = "newuser1@gmail.com";

        MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders
                        .get("/DeleteThenSearch")
                        .param("userid", String.valueOf(userId))
                        .param("keyword", keyword)
                        .param("page", String.valueOf(page))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andReturn();

        String searchMessage = Objects.requireNonNull(mvcResult.getModelAndView()).getModel().get("searchMessage").toString();
        String alertMessage = mvcResult.getModelAndView().getModel().get("alertMessage").toString();

        Object object = mvcResult.getModelAndView().getModel().get("users");

        Assertions.assertThat(object).isNotNull();

        List<User> users = (List<User>) object;

        Assertions.assertThat(searchMessage).isEqualTo("About "+users.size()+" results for \""+keyword+"\"");
        Assertions.assertThat(alertMessage).isEqualTo("UserID "+userId+" has been deleted.");
    }

    @Test
    @WithMockUser(username = "newuser1@gmail.com", authorities = {"Admin"})
    public void testEnableFromSearch() throws Exception {
        int page = 1;
        int userId = 1;
        String keyword = "newuser1@gmail.com";

        MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders
                        .get("/EnableFromSearch")
                        .param("userid", String.valueOf(userId))
                        .param("keyword", keyword)
                        .param("page", String.valueOf(page))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andReturn();

        String searchMessage = Objects.requireNonNull(mvcResult.getModelAndView()).getModel().get("searchMessage").toString();
        String alertMessage = mvcResult.getModelAndView().getModel().get("alertMessage").toString();

        Object object = mvcResult.getModelAndView().getModel().get("users");

        Assertions.assertThat(object).isNotNull();

        List<User> users = (List<User>) object;

        Assertions.assertThat(searchMessage).isEqualTo("About "+users.size()+" results for \""+keyword+"\"");
        Assertions.assertThat(alertMessage).isEqualTo("UserID "+userId+" has been enabled.");
    }

    @Test
    @WithMockUser(username = "newuser1@gmail.com", authorities = {"Admin"})
    public void testDisableFromSearch() throws Exception {
        int page = 1;
        int userId = 1;
        String keyword = "newuser1@gmail.com";

        MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders
                        .get("/DisableFromSearch")
                        .param("userid", String.valueOf(userId))
                        .param("keyword", keyword)
                        .param("page", String.valueOf(page))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andReturn();

        String searchMessage = Objects.requireNonNull(mvcResult.getModelAndView()).getModel().get("searchMessage").toString();
        String alertMessage = mvcResult.getModelAndView().getModel().get("alertMessage").toString();

        Object object = mvcResult.getModelAndView().getModel().get("users");

        Assertions.assertThat(object).isNotNull();

        List<User> users = (List<User>) object;

        Assertions.assertThat(searchMessage).isEqualTo("About "+users.size()+" results for \""+keyword+"\"");
        Assertions.assertThat(alertMessage).isEqualTo("UserID "+userId+" has been disabled.");
    }

    @Test
    @WithMockUser(username = "newuser1@gmail.com", authorities = {"Admin"})
    public void testSearch() throws Exception {
        String keyword = "User Firstname 1";

        List<User> expectedUsers = Collections.singletonList(new User().id(1).email("newuser1@gmail.com").enabled(1)
                .firstName("User Firstname 1").lastName("User Lastname 1"));

        Mockito.when(userService.search(keyword)).thenReturn(expectedUsers);

        MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders
                        .post("/Search")
                        .param("keyword", keyword)
                        .with(csrf()))
                .andReturn();

        String searchMessage = Objects.requireNonNull(mvcResult.getModelAndView()).getModel().get("searchMessage").toString();

        Object object = mvcResult.getModelAndView().getModel().get("users");

        Assertions.assertThat(object).isNotNull();

        List<User> users = (List<User>) object;

        Assertions.assertThat(searchMessage).isEqualTo("About "+users.size()+" results for \""+keyword+"\"");
    }

    @Test
    @WithMockUser(username = "newuser1@gmail.com", authorities = {"Admin"})
    public void testSearchWithPage() throws Exception {

        int page = 1;
        String keyword = "newuser1@gmail.com";

        List<User> expectedUsers = Collections.singletonList(new User().id(1).email("newuser1@gmail.com").enabled(1)
                .firstName("User Firstname 1").lastName("User Lastname 1"));

        Mockito.when(userService.search(keyword)).thenReturn(expectedUsers);

        MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders
                        .get("/Search/"+keyword+"/"+page)
                        .with(csrf()))
                .andReturn();

        String searchMessage = Objects.requireNonNull(mvcResult.getModelAndView()).getModel().get("searchMessage").toString();

        Object object = mvcResult.getModelAndView().getModel().get("users");

        Assertions.assertThat(object).isNotNull();

        List<User> users = (List<User>) object;

        Assertions.assertThat(searchMessage).isEqualTo("About "+users.size()+" results for \""+keyword+"\"");
    }

    @Test
    @WithMockUser(username = "newuser1@gmail.com", authorities = {"Admin"})
    public void testSortFromSearch() throws Exception {
        String keyword = "User Firstname 1";
        int page = 1;

        List<User> expectedUsers = Collections.singletonList(new User().id(1).email("newuser1@gmail.com").enabled(1)
                .firstName("User Firstname 1").lastName("User Lastname 1"));

        Mockito.when(userService.search(keyword))
                .thenReturn(expectedUsers);

        MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders
                        .get("/SortFromSearch/id")
                        .param("keyword", keyword)
                        .param("dir", "desc")
                        .param("page", String.valueOf(page))
                        .with(csrf()))
                .andReturn();

        String searchMessage = Objects.requireNonNull(mvcResult.getModelAndView()).getModel().get("searchMessage").toString();

        Object object = mvcResult.getModelAndView().getModel().get("users");

        Assertions.assertThat(object).isNotNull();

        List<User> users = (List<User>) object;

        Assertions.assertThat(searchMessage).isEqualTo("About "+users.size()+" results for \""+keyword+"\"");
    }

    @Test
    @WithMockUser(username = "newuser1@gmail.com", authorities = {"Editor"})
    public void returnTrueIfEmailIsUnique() throws Exception {
        String email = "newuser0@gmail.com";
        int id = 453;

        Mockito.when(userService.isDuplicate(email)).thenReturn(true);

        String url = "/IsEmailDuplicate";

        mockMvc.perform(
                MockMvcRequestBuilders
                        .get(url)
                        .param("email", email)
                        .param("id", String.valueOf(id))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(content().string("true"));
    }

    @Test
    @WithMockUser(username = "newuser1@gmail.com", authorities = {"Admin"})
    public void testDownloadExcel() throws Exception {
        List<User> users = generate();

        Mockito.when(userService.findAll()).thenReturn(users);

        MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders
                        .get("/ExcelExport"))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andReturn();

        Files.write(Paths.get("users.xlsx"), mvcResult.getResponse().getContentAsByteArray());
    }

    @Test
    @WithMockUser(username = "newuser1@gmail.com", authorities = {"Admin"})
    public void testDownloadCsv() throws Exception {
        List<User> users = generate();

        Mockito.when(userService.findAll()).thenReturn(users);

        MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders
                        .get("/CsvExport"))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andReturn();

        Files.write(Paths.get("users.csv"), mvcResult.getResponse().getContentAsByteArray());
    }

    @Test
    @WithMockUser(username = "newuser1@gmail.com", authorities = {"Admin"})
    public void testDownloadPdf() throws Exception {
        List<User> users = generate();

        Mockito.when(userService.findAll()).thenReturn(users);

        MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders
                        .get("/PdfExport"))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andReturn();

        Files.write(Paths.get("users.pdf"), mvcResult.getResponse().getContentAsByteArray());
    }

    @Test
    @WithMockUser(username = "newuser1@gmail.com", authorities = {"Admin"})
    public void testGetImage() throws Exception {

        int user_id = 57;

        MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders
                        .get("/GetPhoto/"+user_id))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andReturn();

        Files.write(Paths.get("user_"+user_id+".jpg"), mvcResult.getResponse().getContentAsByteArray());
    }

    public List<User> generate() {
        List<User> users = new ArrayList<>();

        users.add(new User().id(1).email("superuser1@gmail.com").enabled(1)
                .firstName("RootUser1").lastName("RootUser1").password("rootuser4567")
                .addRole(new Role(Roles.Admin.name(), Roles.Admin.DESCRIPTION)));

        users.add(new User().id(2).email("superuser2@gmail.com").enabled(1)
                .firstName("RootUser2").lastName("RootUser2").password("rootuser4567")
                .addRole(new Role(Roles.Salesperson.name(), Roles.Salesperson.DESCRIPTION)));

        users.add(new User().id(3).email("superuser3@gmail.com").enabled(1)
                .firstName("RootUser3").lastName("RootUser3").password("rootuser4567")
                .addRole(new Role(Roles.Editor.name(), Roles.Editor.DESCRIPTION)));

        return users;
    }
}