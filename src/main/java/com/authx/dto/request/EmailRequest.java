package com.authx.dto.request;

import lombok.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class EmailRequest {
    private String to;
    private List<String> cc;
    private List<String> bcc;
    private String subject;
    private String textBody;
    private String htmlBody;
    private List<MultipartFile> attachments;
}