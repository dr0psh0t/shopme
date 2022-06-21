package com.shopme.admin.controller;

import com.shopme.admin.entity.User;
import com.shopme.admin.service.UserService;
import com.shopme.admin.utils.Log;
import org.jboss.aerogear.security.otp.Totp;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
public class LoginRestController {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    public LoginRestController(UserService userService, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping(value = "/Authenticate")
    public ResponseEntity<String> authenticate(
            @RequestParam(value = "username") String username,
            @RequestParam(value = "password") String password
    ) {

        User user = userService.findByEmail(username);

        if (user == null) {
            Log.error("User returned is null. Cannot login.");

            return ResponseEntity.ok("{\"msg\":\"User null\", \"success\":false}");
        }

        if (!user.isEnabled()) {
            Log.error("User is disabled. Enable the user to login.");

            return ResponseEntity.ok("{\"msg\":\"User disabled\", \"success\":false}");
        }

        if(!passwordEncoder.matches(password, user.getPassword())) {
            return ResponseEntity.ok("{\"msg\":\"Incorrect username or password\", \"success\":false}");
        }

        if (user.isUsing2FA()) {
            return ResponseEntity.ok("{\"msg\":\"Supply Security Code\", \"success\":true, \"using2fa\":true}");
        } else {
            return ResponseEntity.ok("{\"msg\":\"Go to login\", \"success\":true, \"using2fa\":false}");
        }
    }

    @PostMapping("/Verify")
    public ResponseEntity<String> verify(
            @RequestParam(value = "code") String code,
            @RequestParam(value = "username") String username
    ) {

        User user = userService.findByEmail(username);

        if (!isValidLong(code) || !new Totp(user.getSecret()).verify(code)) {

            Log.error("Invalid security code: "+code);

            return ResponseEntity.ok("{\"msg\":\"Invalid security code\", \"success\":false}");

        } else {

            return ResponseEntity.ok("{\"msg\":\"verified\", \"success\":true}");
        }
    }

    private boolean isValidLong(String code) {
        try {
            Long.parseLong(code);
        } catch (NumberFormatException e) {
            return false;
        }
        return true;
    }
}
