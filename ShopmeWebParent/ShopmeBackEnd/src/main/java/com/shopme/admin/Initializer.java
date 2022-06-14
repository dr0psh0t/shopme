package com.shopme.admin;

import com.shopme.admin.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Profile("!test")
@Component
public class Initializer implements CommandLineRunner {

    private final UserService userService;

    public Initializer(UserService userService) {
        this.userService = userService;
    }

    @Override
    public void run(String... args) throws Exception {
        userService.createUploadsFolder();
    }
}
