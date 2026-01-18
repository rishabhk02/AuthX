package com.authx.service;

import com.sendgrid.*;
import com.sendgrid.helpers.mail.Mail;
import com.sendgrid.helpers.mail.objects.*;
import com.authx.dto.request.EmailRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Base64;

@Service
@Slf4j
@RequiredArgsConstructor
public class SendGridService {
    @Value("${sendgrid.api-key}")
    private String sendgridApiKey;

    @Value("${sendgrid.from-email}")
    private String fromEmail;

    public void sendEmail(EmailRequest request) {
        try {
            Mail mail = buildMail(request);
            SendGrid sg = new SendGrid(sendgridApiKey);
            Request sgRequest = new Request();

            sgRequest.setMethod(Method.POST);
            sgRequest.setEndpoint("mail/send");
            sgRequest.setBody(mail.build());

            Response response = sg.api(sgRequest);
            if (response.getStatusCode() >= 400) {
                throw new RuntimeException("SendGrid failed: " + response.getStatusCode());
            }
            log.info("Email sent successfully to {} (Status: {})", request.getTo(), response.getStatusCode());
        } catch (Exception ex) {
            log.error("Failed to send email to {}: {}", request.getTo(), ex.getMessage(), ex);
            throw new RuntimeException("Email sending failed", ex);
        }
    }

    private Mail buildMail(EmailRequest request) {
        Email from = new Email(fromEmail);
        Content content = getContent(request);

        // Personalization (To / CC / BCC)
        Personalization personalization = new Personalization();
        personalization.addTo(new Email(request.getTo()));

        if (request.getCc() != null) {
            request.getCc().forEach(cc -> personalization.addCc(new Email(cc)));
        }

        if (request.getBcc() != null) {
            request.getBcc().forEach(bcc -> personalization.addBcc(new Email(bcc)));
        }

        Mail mail = new Mail();
        mail.setFrom(from);
        mail.setSubject(request.getSubject());
        mail.addPersonalization(personalization);
        mail.addContent(content);

        // Attachments
        if (request.getAttachments() != null) {
            request.getAttachments().forEach(file -> addAttachment(mail, file));
        }

        return mail;
    }



    private void addAttachment(Mail mail, MultipartFile file) {
        try {
            Attachments attachment = new Attachments();
            attachment.setContent(encodeFileToBase64(file.getBytes()));
            attachment.setType(file.getContentType());
            attachment.setFilename(file.getOriginalFilename());
            attachment.setDisposition("attachment");

            mail.addAttachments(attachment);
        } catch (IOException e) {
            log.error("Failed to attach file: {}", file.getOriginalFilename(), e);
        }
    }


    private Content getContent(EmailRequest request) {
        if (request.getHtmlBody() != null && !request.getHtmlBody().isEmpty()) {
            return new Content("text/html", request.getHtmlBody());
        }
        return new Content("text/plain", request.getTextBody());
    }

    private String encodeFileToBase64(byte[] fileBytes) {
        return Base64.getEncoder().encodeToString(fileBytes);
    }
}
