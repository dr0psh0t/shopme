package com.shopme.admin.controller;

import com.shopme.admin.entity.User;
import com.shopme.admin.service.UserService;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class UserRestController {

    private UserService userService;

    public UserRestController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/IsEmailDuplicate")
    public ResponseEntity<Boolean> isEmailDuplicate(
            @RequestParam("email") String email, @RequestParam("id") int id) {
        return ResponseEntity.ok(userService.isDuplicate(email) && !userService.ownerOwnedEmail(email, id));
    }

    @GetMapping("/SearchUsersWithPage")
    public ResponseEntity<List<User>> searchRest(
            @RequestParam("keyword") String keyword,
            @RequestParam("pageNo") int pageNo) {

        return ResponseEntity.ok(userService.findPageByKeyword(keyword, pageNo).getContent());
    }

    @GetMapping("/SearchUsers")
    public ResponseEntity<List<User>> searchCriteria(@RequestParam("keyword") String keyword) {
        return ResponseEntity.ok(userService.search(keyword));
    }
}