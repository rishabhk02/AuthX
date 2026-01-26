package com.authx.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class RabbitMQService {
    
    private final RabbitTemplate rabbitTemplate;
    
    // Queue and exchange constants
    public static final String EMAIL_QUEUE = "email.queue";
    public static final String EMAIL_EXCHANGE = "email.exchange";
    public static final String EMAIL_ROUTING_KEY = "email.routing.key";

    /**
     * Send message to a specific queue
     */
    public void sendMessage(String exchange, String routingKey, Object message) {
        try {
            rabbitTemplate.convertAndSend(exchange, routingKey, message);
            log.debug("Message sent to exchange: {}, routingKey: {}", exchange, routingKey);
        } catch (Exception e) {
            log.error("Failed to send message to queue: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to send message to queue", e);
        }
    }

    /**
     * Send email to email queue
     */
    public void sendEmail(Object emailRequest) {
        sendMessage(EMAIL_EXCHANGE, EMAIL_ROUTING_KEY, emailRequest);
        log.info("Email queued successfully");
    }
}
