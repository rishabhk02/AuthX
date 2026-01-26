package com.authx.service.email;

import com.authx.dto.request.EmailRequest;
import com.authx.service.RabbitMQService;
import com.authx.service.SendGridService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class EmailConsumerService {
    
    private final SendGridService sendGridService;

    @RabbitListener(queues = RabbitMQService.EMAIL_QUEUE)
    public void consumeEmail(EmailRequest emailRequest) {
        try {
            log.info("Processing email for: {}", emailRequest.getTo());

            sendGridService.sendEmail(emailRequest);
            
            log.info("Email sent successfully to: {}", emailRequest.getTo());
            
        } catch (Exception e) {
            log.error("Failed to process email for {}: {}", 
                    emailRequest.getTo(), e.getMessage(), e);
            // RabbitMQ will requeue the message based on retry policy
            throw new RuntimeException("Email processing failed", e);
        }
    }
}
