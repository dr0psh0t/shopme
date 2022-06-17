package com.shopme.admin.service;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletResponse;

import com.shopme.admin.entity.User;
import org.springframework.core.io.Resource;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

@Service
public interface UserService {

    void createUploadsFolder();

    Resource getResource(String filename);

    void deleteAll();

    void saveUser(User rootUser);

    User saveUser(User user, ArrayList<Integer> enableList, ArrayList<Integer> rolesList, MultipartFile photo,
                  boolean isUpdate) throws IOException;

    User register(User user, ArrayList<Integer> enableList, ArrayList<Integer> rolesList, MultipartFile photo,
                  int isUsing2FA) throws IOException;

    void saveRole(String name, String description);

    void addRoleToUser(String username, String roleName);

    User findByEmail(String Email);

    List<User> findAll();

    void deleteById(int userId);

    User findById(int userId);

    void displayFileFromFolder(int id, HttpServletResponse response) throws IOException;

    void enable(int userid);

    void disable(int userid);

    List<User> findByEmailLike(String email);

    List<User> findByFirstnameLike(String firstname);

    List<User> findByLastnameLike(String lastname);

    List<User> sortPage(String field, String direction, int page);

    Page<User> findPage(int pageNumber);

    Page<User> getPageAndSort(String field, String direction, int pageNumber);

    Page<User> findPageByKeyword(String keyword, int pageNo);

    ArrayList<User> sortList(ArrayList<User> users, String field, String direction);

    boolean isDuplicate(String email);

    boolean ownerOwnedEmail(String email, int id);

    List<User> search(String keyword);

    String generateQRUrl(User user) throws UnsupportedEncodingException;

    //String findSecretBySecret()
}
