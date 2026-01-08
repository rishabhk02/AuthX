package com.authx.dto.response;

import lombok.*;

@Data
@AllArgsConstructor
@Builder
public class EmailVerificationResponse {
    private String message;
}