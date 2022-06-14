package com.shopme.admin.controller;

import com.shopme.admin.config.ShopmeBackendSecurityConfig;
import com.shopme.admin.entity.Roles;
import com.shopme.admin.service.RoleService;
import com.shopme.admin.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest
@ContextConfiguration(classes = {MainController.class, ShopmeBackendSecurityConfig.class})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@ActiveProfiles("test")
@Rollback(value = false)
public class MainControllerTest {

    @Autowired WebApplicationContext context;

    @Autowired private MockMvc mockMvc;

    @MockBean BCryptPasswordEncoder bCryptPasswordEncoder;

    @MockBean private UserDetailsService userDetailsService;

    @Test public void testLoginIfRedirection() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders
                        .post("/authenticateTheUser")
                        .param("username", "newuser1@gmail.com")
                        .param("password", "newuser1@gmail.com")
                        .with(csrf()))
                .andExpect(status().is3xxRedirection());
    }

    @Test public void testLogoutIfRedirection() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders
                        .post("/Logout")
                        .with(csrf()))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    public void mockRoot() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/").with(csrf())).andExpect(status().is3xxRedirection());
    }

    @Test @WithMockUser(username = "newuser1@gmail.com", authorities = {"Admin"})
    public void mockFragment() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/Fragments").with(csrf())).andExpect(status().isOk());
    }

    @Test @WithMockUser(username = "newuser1@gmail.com", authorities = {"Admin"})
    public void mockCategories() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/Categories").with(csrf())).andExpect(status().isOk());
    }

    @Test @WithMockUser(username = "newuser1@gmail.com", authorities = {"Admin"})
    public void mockBrands() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/Brands").with(csrf())).andExpect(status().isOk());
    }

    @Test @WithMockUser(username = "newuser1@gmail.com", authorities = {"Admin"})
    public void mockProducts() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/Products").with(csrf())).andExpect(status().isOk());
    }

    @Test @WithMockUser(username = "newuser1@gmail.com", authorities = {"Admin"})
    public void mockCustomers() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/Customers").with(csrf())).andExpect(status().isOk());
    }

    @Test @WithMockUser(username = "newuser1@gmail.com", authorities = {"Admin"})
    public void mockShipping() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/Shipping").with(csrf())).andExpect(status().isOk());
    }

    @Test @WithMockUser(username = "newuser1@gmail.com", authorities = {"Admin"})
    public void mockSalesReport() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/SalesReport").with(csrf())).andExpect(status().isOk());
    }

    @Test @WithMockUser(username = "newuser1@gmail.com", authorities = {"Admin"})
    public void mockArticles() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/Articles").with(csrf())).andExpect(status().isOk());
    }

    @Test @WithMockUser(username = "newuser1@gmail.com", authorities = {"Admin"})
    public void mockMenus() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/Menus").with(csrf())).andExpect(status().isOk());
    }

    @Test @WithMockUser(username = "newuser1@gmail.com", authorities = {"Admin"})
    public void mockSettings() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/Settings").with(csrf())).andExpect(status().isOk());
    }

    @Test @WithMockUser(username = "newuser1@gmail.com", authorities = {"Admin"})
    public void mocProfile() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/Profile").with(csrf())).andExpect(status().isOk());
    }
}
