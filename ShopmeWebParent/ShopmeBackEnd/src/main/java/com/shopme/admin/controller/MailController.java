package com.shopme.admin.controller;

import com.shopme.admin.service.EmailService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MailController {

    private final EmailService emailService;

    public MailController(EmailService emailService) {
        this.emailService = emailService;
    }

    @GetMapping("/mail/sendmail")
    public String sendEmailMessage() {
        emailService.sendMessage(
                "daryll.david@fullspeedtechnologies.com",
                "Greetings Youtube community!",
                "I hope you're enjoying this live coding session."
        );

        return "Message sent";
    }
}
