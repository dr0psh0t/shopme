package com.shopme.admin.domain;

public class JsonResponse {
    private final String msg;
    private final boolean success;

    public JsonResponse(String msg, boolean success) {
        this.msg = msg;
        this.success = success;
    }
}
