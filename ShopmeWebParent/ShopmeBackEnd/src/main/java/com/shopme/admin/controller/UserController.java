package com.shopme.admin.controller;

import com.shopme.admin.entity.User;
import com.shopme.admin.service.*;
import com.shopme.admin.utils.Log;
import org.apache.tomcat.util.http.fileupload.IOUtils;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import javax.websocket.server.PathParam;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Controller
public class UserController {

    private final RoleService roleService;
    private final UserService userService;

    public UserController(RoleService roleService, UserService userService) {
        this.roleService = roleService;
        this.userService = userService;
    }
     
    @GetMapping("/GetPhoto/{id}")
    public void getImageFromDb(@PathVariable(value = "id") int id, HttpServletResponse response)
            throws IOException {
        userService.displayFileFromFolder(id, response);
    }

    @PostMapping("/SaveUser")
    public String saveUser(
            @Valid @ModelAttribute("user") User user, Errors errors,
            @RequestParam(value = "roles", required = false) ArrayList<Integer> roles,
            @RequestParam(value = "photo", required = false) MultipartFile photo,
            @RequestParam(value = "enabled") ArrayList<Integer> enabled,
            @RequestParam(value = "isUpdate") boolean isUpdate,
            @RequestParam(value = "page") int page, Model model
    ) throws IOException {

        model.addAttribute("rolesList", roleService.findAll());
        model.addAttribute("isUpdate", isUpdate);
        model.addAttribute("page", page);

        if (roles == null) {
            model.addAttribute("roleEmptyError", "Select at least 1 role");
            return "user-form";
        }

        if (errors.hasErrors()) {
            if (errors.getErrorCount() == 1) {
                if (errors.getFieldError("password") != null) {
                    if (!isUpdate) {
                        return "user-form";
                    }
                } else {
                    return "user-form";
                }
            } else {
                return "user-form";
            }
        }

        userService.saveUser(user, enabled, roles, photo, isUpdate);

        String message = "UserID "+user.getId()+" has been "+(isUpdate ? "Updated." : "Added.");

        model.addAttribute("alertMessage", message);

        Log.info(message);

        return getOnePage(model, isUpdate ? page : 1);
    }
     
    @GetMapping("/AddUserForm")
    public String addUserForm(Model model) {
        model.addAttribute("user", new User().enabled(1));
        model.addAttribute("rolesList", roleService.findAll());
        model.addAttribute("isUpdate", false);

        return "user-form";
    }
     
    @GetMapping("/UpdateUserForm")
    public String updateUserForm(@RequestParam("userId") int userId, @RequestParam("page") int page, Model model) {
        model.addAttribute("user", userService.findById(userId));
        model.addAttribute("rolesList", roleService.findAll());
        model.addAttribute("isUpdate", true);
        model.addAttribute("page", page);

        return "user-form";
    }
     
    @GetMapping("/DeleteUser")
    public String delete(@RequestParam("userId") int userId, Model model) {
        userService.deleteById(userId);

        model.addAttribute("alertMessage", "UserId "+userId+" has been deleted.");
        Log.info("Deleted "+userId);

        return users(model);
    }

    @GetMapping("/Enable")
    public String enable(@RequestParam(value = "userid") int userid,
                         @RequestParam(value = "page") int page,
                         Model model) {
        userService.enable(userid);

        model.addAttribute("alertMessage", "UserID "+userid+" has been enabled.");
        Log.info("Enabled user id "+userid);
        return getOnePage(model, page);
    }

    @GetMapping("/Disable")
    public String disable(@RequestParam(value = "userid") int userid,
                          @RequestParam(value = "page") int page,
                          Model model) {
        userService.disable(userid);

        model.addAttribute("alertMessage", "UserID "+userid+" has been disabled.");
        Log.info("Disabled user id "+userid);
        return getOnePage(model, page);
    }

    @GetMapping("/SortFromSearch/{field}")
    public String sortFromSearch(@RequestParam(value = "keyword") String keyword,
                                 @PathVariable String field,
                                 @PathParam("dir") String dir,
                                 @RequestParam(value = "page") int page,
                                 Model model) {

        Page<User> userPage = userService.findPageByKeyword(keyword, page);

        int totalPages = userPage != null ? userPage.getTotalPages() : 1;
        long totalItems = userPage != null ? userPage.getTotalElements() : 0;
        List<User> users = userPage != null ? userPage.getContent() : new ArrayList<>();

        List<User> modifiedList = userService.sortList(new ArrayList<>(users), field, dir);

        model.addAttribute("currentPage", page);
        model.addAttribute("totalPages", totalPages);
        model.addAttribute("totalItems", totalItems);
        model.addAttribute("reverseSortDir", dir.equalsIgnoreCase("asc") ? "desc" : "asc");
        model.addAttribute("users", modifiedList);
        model.addAttribute("isSearching", true);
        model.addAttribute("keyword", keyword);
        model.addAttribute("searchMessage", "About "+(users.size()*totalPages)+" results for \""+keyword+"\"");

        Log.info("About "+modifiedList.size()+" results for \""+keyword+"\"");

        return "users";
    }

    @GetMapping("/DeleteThenSearch")
    public String deleteFromSearch(@RequestParam(value = "userid") int userid,
                                   @RequestParam(value = "keyword") String keyword,
                                   @RequestParam(value = "page") int page,
                                   Model model) {
        userService.deleteById(userid);

        Page<User> userPage = userService.findPageByKeyword(keyword, page);

        int totalPages = userPage != null ? userPage.getTotalPages() : 1;
        long totalItems = userPage != null ? userPage.getTotalElements() : 0;
        List<User> users = userPage != null ? userPage.getContent() : new ArrayList<>();

        model.addAttribute("currentPage", page);
        model.addAttribute("totalPages", totalPages);
        model.addAttribute("totalItems", totalItems);
        model.addAttribute("reverseSortDir", "asc");
        model.addAttribute("users", users);
        model.addAttribute("isSearching", true);
        model.addAttribute("keyword", keyword);
        model.addAttribute("searchMessage", "About "+(users.size()*totalPages)+" results for \""+keyword+"\"");
        model.addAttribute("alertMessage", "UserID "+userid+" has been deleted.");

        Log.info("Deleted userid "+userid);
        return "users";
    }

    @GetMapping("/EnableFromSearch")
    public String enableFromSearch(Model model,
                                   @RequestParam(value = "userid") int userid,
                                   @RequestParam(value = "keyword") String keyword,
                                   @RequestParam(value = "page") int page) {
        userService.enable(userid);

        Page<User> userPage = userService.findPageByKeyword(keyword, page);

        int totalPages = userPage != null ? userPage.getTotalPages() : 1;
        long totalItems = userPage != null ? userPage.getTotalElements() : 0;
        List<User> users = userPage != null ? userPage.getContent() : new ArrayList<>();

        model.addAttribute("currentPage", page);
        model.addAttribute("totalPages", totalPages);
        model.addAttribute("totalItems", totalItems);
        model.addAttribute("reverseSortDir", "asc");
        model.addAttribute("users", users);
        model.addAttribute("isSearching", true);
        model.addAttribute("keyword", keyword);
        model.addAttribute("searchMessage", "About "+(users.size()*totalPages)+" results for \""+keyword+"\"");
        model.addAttribute("alertMessage", "UserID "+userid+" has been enabled.");

        Log.info("Enabled user id "+userid);
        return "users";
    }

    @GetMapping("/DisableFromSearch")
    public String disableFromSearch(Model model,
                                    @RequestParam(value = "userid") int userid,
                                    @RequestParam(value = "keyword") String keyword,
                                    @RequestParam(value = "page") int page) {
        userService.disable(userid);

        Page<User> userPage = userService.findPageByKeyword(keyword, page);

        int totalPages = userPage != null ? userPage.getTotalPages() : 1;
        long totalItems = userPage != null ? userPage.getTotalElements() : 0;
        List<User> users = userPage != null ? userPage.getContent() : new ArrayList<>();

        model.addAttribute("currentPage", page);
        model.addAttribute("totalPages", totalPages);
        model.addAttribute("totalItems", totalItems);
        model.addAttribute("reverseSortDir", "asc");
        model.addAttribute("users", users);
        model.addAttribute("isSearching", true);
        model.addAttribute("keyword", keyword);
        model.addAttribute("searchMessage", "About "+(users.size()*totalPages)+" results for \""+keyword+"\"");
        model.addAttribute("alertMessage", "UserID "+userid+" has been disabled.");

        Log.info("Disabled user id "+userid);
        return "users";
    }

    @PostMapping("/Search")
    public String search(@RequestParam(value = "keyword") String keyword, Model model) {

        Page<User> userPage = userService.findPageByKeyword(keyword, 1);

        int totalPages = userPage != null ? userPage.getTotalPages() : 1;
        long totalItems = userPage != null ? userPage.getTotalElements() : 0;
        List<User> users = userPage != null ? userPage.getContent() : new ArrayList<>();

        model.addAttribute("currentPage", 1);
        model.addAttribute("totalPages", totalPages);
        model.addAttribute("totalItems", totalItems);
        model.addAttribute("reverseSortDir", "asc");
        model.addAttribute("users", users);
        model.addAttribute("isSearching", true);
        model.addAttribute("keyword", keyword);
        model.addAttribute("searchMessage", "About "+(users.size()*totalPages)+" results for \""+keyword+"\"");

        return "users";
    }

    @GetMapping("/Search/{keyword}/{page}")
    public String searchByPage(
            @PathVariable(value = "keyword") String keyword,
            @PathVariable("page") int page,
            Model model) {

        Page<User> userPage = userService.findPageByKeyword(keyword, page);

        int totalPages = userPage != null ? userPage.getTotalPages() : 1;
        long totalItems = userPage != null ? userPage.getTotalElements() : 0;
        List<User> users = userPage != null ? userPage.getContent() : new ArrayList<>();

        model.addAttribute("currentPage", page);
        model.addAttribute("totalPages", totalPages);
        model.addAttribute("totalItems", totalItems);
        model.addAttribute("reverseSortDir", "asc");
        model.addAttribute("users", users);
        model.addAttribute("isSearching", true);
        model.addAttribute("keyword", keyword);
        model.addAttribute("searchMessage", "About "+(users.size()*totalPages)+" results for \""+keyword+"\"");

        return "users";
    }

    @GetMapping("/Users")
    public String users(Model model) {
        return getOnePage(model, 1);
    }

    @GetMapping("/Users/{pageNumber}")
    public String getOnePage(Model model, @PathVariable("pageNumber") int currentPage) {
        Page<User> page = userService.findPage(currentPage);

        int totalPages = page != null ? page.getTotalPages() : 1;
        long totalItems = page != null ? page.getTotalElements() : 0;
        List<User> users = page != null ? page.getContent() : new ArrayList<>();

        model.addAttribute("currentPage", currentPage);
        model.addAttribute("totalPages", totalPages);
        model.addAttribute("totalItems", totalItems);
        model.addAttribute("reverseSortDir", "asc");
        model.addAttribute("users", users);
        model.addAttribute("isSearching", false);

        return "users";
    }

    @GetMapping("/Users/{pageNumber}/{field}")
    public String getPageAndSort(Model model,
                                  @RequestParam(value = "single") boolean single,
                                  @PathVariable("pageNumber") int currentPage,
                                  @PathVariable String field,
                                  @PathParam("sortDir") String sortDir) {

        Page<User> page = single
                ? userService.findPage(currentPage)
                : userService.getPageAndSort(field, sortDir, currentPage);

        int totalPages = page != null ? page.getTotalPages() : 1;
        long totalItems = page != null ? page.getTotalElements() : 0;
        List<User> users = page != null ? page.getContent() : new ArrayList<>();

        model.addAttribute("currentPage", currentPage);
        model.addAttribute("totalPages", totalPages);
        model.addAttribute("totalItems", totalItems);

        if (sortDir != null) {
            model.addAttribute("sortDir", sortDir);
            model.addAttribute("reverseSortDir", sortDir.equals("asc") ? "desc" : "asc");
        } else {
            model.addAttribute("sortDir", "asc");
            model.addAttribute("reverseSortDir", "asc");
        }

        model.addAttribute("users", single
                ? userService.sortList(new ArrayList<>(users), field, sortDir)
                : users);
        model.addAttribute("isSearching", false);
        model.addAttribute("field", field);

        return "users";
    }

    @GetMapping("/CsvExport")
    public void downloadCsv(HttpServletResponse response) {
        new UserCSVExporter(userService.findAll()).exportToCsv(response);
        Log.info("Exporting users.csv");
    }

    @GetMapping("/ExcelExport")
    public void downloadExcel(HttpServletResponse response) throws IOException {
        response.setContentType("application/octet-stream");
        response.setHeader("Content-Disposition", "attachment; filename=users.xlsx");

        IOUtils.copy(new UserExcelExporter(userService.findAll()).exportToExcel(), response.getOutputStream());
        Log.info("Exporting users.xlsx");
    }

    @GetMapping("/PdfExport")
    public void downloadPdf(HttpServletResponse response) {
        new UserPDFExporter(userService.findAll()).exportToPdf(response);
        Log.info("Exporting users.pdf");
    }
}