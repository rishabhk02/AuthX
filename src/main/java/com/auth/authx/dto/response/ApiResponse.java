package com.authx.dto.response;

import lombok.*;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ApiResponse<T> {
    private String status;
    private int statusCode;
    private String message;
    private T data;
    private Long timestamp;

    public static <T> ApiResponse<T> response(String message, String status){
        return response(message, status, 200, null);
    }

    public static <T> ApiResponse<T> response(String message, String status, int statusCode){
        return response(message, status, statusCode, null);
    }

    public static <T> ApiResponse<T> response(String message, String status, int statusCode, T data){
        return ApiResponse.<T>builder()
                .status(status)
                .statusCode(statusCode)
                .data(data)
                .timestamp(System.currentTimeMillis())
                .build();
    }
}