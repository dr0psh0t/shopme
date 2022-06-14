package com.shopme.admin;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@ActiveProfiles("test")
class ShopmeBackEndApplicationTest {

    @Autowired private MockMvc mockMvc;

    @Test public void testUsersIfStatusIsOk() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/Users").with(csrf()))
                .andExpect(status().isOk());
    }
}