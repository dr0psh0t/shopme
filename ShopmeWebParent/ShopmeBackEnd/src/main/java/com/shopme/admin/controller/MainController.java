package com.shopme.admin.controller;

import com.shopme.admin.utils.Log;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Controller
public class MainController {

	public MainController() {}

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