package com.authx.dto.response;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EmailVerificationResponse {
    private String message;
}