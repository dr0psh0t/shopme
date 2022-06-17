package com.shopme.admin.controller;

import com.shopme.admin.entity.User;
import com.shopme.admin.service.RoleService;
import com.shopme.admin.service.UserService;
import com.shopme.admin.utils.Log;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.io.IOException;
import java.util.ArrayList;

@Controller
public class MainController {

	private final RoleService roleService;
	private final UserService userService;

	public MainController(RoleService roleService, UserService userService) {
		this.roleService = roleService;
		this.userService = userService;
	}

	@GetMapping("/")
	public String root() {
		return "redirect:/Users";
	}

	@GetMapping("/AccessDenied")
	public String accessDenied() {
		return "access-denied";
	}

	@GetMapping("/ErrorPage")
	public String errorPage() {
		return "error-page";
	}

	@GetMapping("/Login")
	public String login() {
		return "login";
	}

	@GetMapping("/Logout")
	public String logout(HttpServletRequest request, HttpServletResponse response, Model model) {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();

		if (auth != null) {
			new SecurityContextLogoutHandler().logout(request, response, auth);
			model.addAttribute("logout", "Signing out "+auth.getName());
			Log.info(auth.getName()+" has logged out");
		}

		return "redirect:/Login";
	}

	@GetMapping("/Registration")
	public String registration(Model model) {
		model.addAttribute("user", new User().enabled(1).firstName("Daryll").lastName("Dagondon")
				.email("dagondondaryll@gmail.com").password("dagondondaryll@gmail.com"));
		model.addAttribute("rolesList", roleService.findAll());
		return "registration";
	}

	@PostMapping("/RegisterUser")
	public String registerUser(
			@Valid @ModelAttribute("user") User user, Errors errors,
		   	@RequestParam(value = "roles", required = false) ArrayList<Integer> roles,
		   	@RequestParam(value = "photo", required = false) MultipartFile photo,
		   	@RequestParam(value = "enabled") ArrayList<Integer> enabled,
			@RequestParam(value = "using2FA") int using2FA,
		   	Model model
	) throws IOException {

		/*
		System.out.println("user="+user);
		System.out.println("roles="+roles);
		System.out.println("enabled="+enabled);
		System.out.println("photo="+photo.getName());
		System.out.println("using2FA="+using2FA);
		errors.getFieldErrors().forEach(error -> System.out.println(error));
		 */

		model.addAttribute("rolesList", roleService.findAll());

		if (roles == null) {
			model.addAttribute("roleEmptyError", "Select at least 1 role");
			return "registration";
		}

		if (errors.hasErrors()) {
			return "registration";
		}

		User newUser = userService.register(user, enabled, roles, photo, using2FA);
		Log.info("Successfully registered "+newUser.getEmail());

		if (newUser.isUsing2FA()) {
			model.addAttribute("qr", userService.generateQRUrl(user));
			return "qrcode";
		} else {
			return "redirect:/Login";
		}
	}

	@GetMapping("/QrCode")
	public String qrcode() {
		return "qrcode";
	}

	@PostMapping("/Register")
	public String register() {
		return "";
	}

	@GetMapping("/Fragments")
	public String header() {
		return "fragments";
	}

	@GetMapping("/Categories")
	public String categories() {
		return "categories";
	}

	@GetMapping("/Brands")
	public String brands() {
		return "brands";
	}

	@GetMapping("/Products")
	public String products() {
		return "products";
	}

	@GetMapping("/Customers")
	public String customers() {
		return "customers";
	}

	@GetMapping("/Shipping")
	public String shipping() {
		return "shipping";
	}

	@GetMapping("/Orders")
	public String orders() {
		return "orders";
	}

	@GetMapping("/SalesReport")
	public String salesReport() {
		return "sales-report";
	}

	@GetMapping("/Articles")
	public String articles() {
		return "articles";
	}

	@GetMapping("/Menus")
	public String menus() {
		return "menus";
	}

	@GetMapping("/Settings")
	public String settings() {
		return "settings";
	}

	@GetMapping("/Profile")
	public String profile() {
		return "profile";
	}
}