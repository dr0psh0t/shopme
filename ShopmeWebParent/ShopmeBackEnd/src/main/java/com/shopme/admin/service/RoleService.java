package com.shopme.admin.service;

import com.shopme.admin.entity.Role;

import java.util.ArrayList;
import java.util.List;

public interface RoleService {

	List<Role> findAll();

	Role findOne(int id);

	Role findByName(String name);

	void deleteAll();

	void fillRoles();

	ArrayList<Integer> getRolesIds();
}
