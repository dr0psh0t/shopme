package com.shopme.admin.entity;

public enum Roles {

    Admin("Manage everything"),
    Salesperson("Manage product price, customers, shipping, orders and sales report"),
    Editor("Manage categories, brands, products, articles and menus"),
    Shipper("View products, view orders and update order status"),
    Assistant("Manage product price, customers, shipping, orders and sales report");

    public final String DESCRIPTION;

    Roles(String description) {
        this.DESCRIPTION = description;
    }
}
