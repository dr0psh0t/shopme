package com.shopme.admin.domain;

import com.shopme.admin.entity.User;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Component;

@Component
public class UserSpecification {

    public Specification<User> idSpec(String key) {
        return (root, query, criteriaBuilder) -> criteriaBuilder.like(root.get("id").as(String.class), "%"+key+"%");
    }

    public Specification<User> emailSpec(String key) {
        return (root, query, criteriaBuilder) -> criteriaBuilder.like(root.get("email"), "%"+key+"%");
    }

    public Specification<User> fnameSpec(String key) {
        return (root, query, criteriaBuilder) -> criteriaBuilder.like(root.get("firstName"), "%"+key+"%");
    }

    public Specification<User> lnameSpec(String key) {
        return (root, query, criteriaBuilder) -> criteriaBuilder.like(root.get("lastName"), "%"+key+"%");
    }
}
