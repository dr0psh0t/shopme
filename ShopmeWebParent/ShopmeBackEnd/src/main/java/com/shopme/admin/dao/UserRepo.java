package com.shopme.admin.dao;

import com.shopme.admin.entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserRepo extends JpaRepository<User, Integer>, JpaSpecificationExecutor<User> {

    Page<User> findAll(Specification<User> spec, Pageable pageable);

    List<User> findAll(Specification<User> spec);

    User findByEmail(String email);

    @Query("SELECT u FROM User u WHERE u.email LIKE %:email%")
    List<User> searchByEmailLike(@Param("email") String email);

    @Query("SELECT u FROM User u WHERE u.firstName LIKE %:firstname%")
    List<User> searchByFirstnameLike(@Param("firstname") String firstname);

    @Query("SELECT u FROM User u WHERE u.lastName LIKE %:lastname%")
    List<User> searchByLastnameLike(@Param("lastname") String lastname);
}
