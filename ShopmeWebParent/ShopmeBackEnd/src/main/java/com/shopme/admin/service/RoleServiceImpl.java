package com.shopme.admin.service;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import javax.transaction.Transactional;

import com.shopme.admin.dao.RoleRepo;
import com.shopme.admin.entity.Role;
import com.shopme.admin.entity.Roles;
import org.springframework.stereotype.Service;

@Service
@Transactional
public class RoleServiceImpl implements RoleService {
	
	private final RoleRepo roleRepo;
	
	public RoleServiceImpl(RoleRepo roleRepo) {
		this.roleRepo = roleRepo;
	}

	@Override
	public List<Role> findAll() {
		return roleRepo.findAll();
	}

	@Override
	public Role findOne(int id) {
		return roleRepo.findById(id).orElseThrow(RuntimeException::new);
	}

	@Override
	public Role findByName(String name) {
		return roleRepo.findByName(name);
	}

	public void deleteAll() {
		roleRepo.deleteAll();
	}

	@Override
	public void fillRoles() {
		roleRepo.save(new Role(Roles.Admin.name(), Roles.Admin.DESCRIPTION));
		roleRepo.save(new Role(Roles.Salesperson.name(), Roles.Salesperson.DESCRIPTION));
		roleRepo.save(new Role(Roles.Editor.name(), Roles.Editor.DESCRIPTION));
		roleRepo.save(new Role(Roles.Shipper.name(), Roles.Shipper.DESCRIPTION));
		roleRepo.save(new Role(Roles.Assistant.name(), Roles.Assistant.DESCRIPTION));
	}

	@Override
	public ArrayList<Integer> getRolesIds() {
		return roleRepo.findAll().stream().map(Role::getId).collect(Collectors.toCollection(ArrayList::new));
	}
}