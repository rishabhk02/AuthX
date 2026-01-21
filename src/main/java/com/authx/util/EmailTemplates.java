package com.authx.util;

public final class EmailTemplates {
    private EmailTemplates() {
        throw new UnsupportedOperationException("Utility class - cannot instantiate!");
    }

    public static final String VERIFICATION_EMAIL = "<!DOCTYPE html>\n" +
            "<html>\n" +
            "<head>\n" +
            "    <meta charset=\"UTF-8\">\n" +
            "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n" +
            "    <title>Verify your email - AuthX</title>\n" +
            "</head>\n" +
            "<body style=\"margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #f8f9fa;\">\n"
            +
            "    <table role=\"presentation\" width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" border=\"0\" style=\"background-color: #f8f9fa;\">\n"
            +
            "        <!-- Header -->\n" +
            "        <tr>\n" +
            "            <td style=\"padding: 40px 20px 20px;\">\n" +
            "                <table role=\"presentation\" align=\"center\" width=\"600\" cellspacing=\"0\" cellpadding=\"0\" border=\"0\">\n"
            +
            "                    <tr>\n" +
            "                        <td style=\"text-align: center; padding-bottom: 20px;\">\n" +
            "                            <h1 style=\"margin: 0; font-size: 28px; font-weight: 700; color: #1a1a1a;\">Welcome to <span style=\"color: #6366f1;\">AuthX</span></h1>\n"
            +
            "                        </td>\n" +
            "                    </tr>\n" +
            "                </table>\n" +
            "            </td>\n" +
            "        </tr>\n" +
            "        \n" +
            "        <!-- Content -->\n" +
            "        <tr>\n" +
            "            <td style=\"padding: 0 20px 40px;\">\n" +
            "                <table role=\"presentation\" align=\"center\" width=\"600\" cellspacing=\"0\" cellpadding=\"0\" border=\"0\" style=\"background-color: white; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.08);\">\n"
            +
            "                    <tr>\n" +
            "                        <td style=\"padding: 60px 50px 40px;\">\n" +
            "                            <h2 style=\"margin: 0 0 20px; font-size: 24px; font-weight: 600; color: #1a1a1a;\">Verify your email address</h2>\n"
            +
            "                            <p style=\"margin: 0 0 30px; font-size: 16px; line-height: 1.6; color: #4b5563;\">\n"
            +
            "                                Hi <strong>${username}</strong>,<br><br>\n" +
            "                                Thanks for signing up with <strong>AuthX</strong>! To get started, please verify your email address by clicking the button below.\n"
            +
            "                            </p>\n" +
            "                            \n" +
            "                            <!-- Verify Button -->\n" +
            "                            <table role=\"presentation\" align=\"center\" width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" border=\"0\">\n"
            +
            "                                <tr>\n" +
            "                                    <td style=\"text-align: center; padding: 30px 0;\">\n" +
            "                                        <a href=\"${verificationUrl}\" \n" +
            "                                           style=\"display: inline-block; padding: 16px 40px; background-color: #6366f1; color: white; text-decoration: none; font-size: 16px; font-weight: 600; border-radius: 8px; box-shadow: 0 4px 12px rgba(99, 102, 241, 0.3); transition: all 0.2s;\">\n"
            +
            "                                            Verify Email Address\n" +
            "                                        </a>\n" +
            "                                    </td>\n" +
            "                                </tr>\n" +
            "                            </table>\n" +
            "                            \n" +
            "                            <p style=\"margin: 30px 0 0; font-size: 14px; line-height: 1.6; color: #6b7280; text-align: center;\">\n"
            +
            "                                Or copy and paste this link into your browser:<br>\n" +
            "                                <a href=\"${verificationUrl}\" style=\"color: #6366f1; word-break: break-all;\">${verificationUrl}</a>\n"
            +
            "                            </p>\n" +
            "                        </td>\n" +
            "                    </tr>\n" +
            "                </table>\n" +
            "            </td>\n" +
            "        </tr>\n" +
            "        \n" +
            "        <!-- Footer -->\n" +
            "        <tr>\n" +
            "            <td style=\"padding: 40px 20px;\">\n" +
            "                <table role=\"presentation\" align=\"center\" width=\"600\" cellspacing=\"0\" cellpadding=\"0\" border=\"0\">\n"
            +
            "                    <tr>\n" +
            "                        <td style=\"text-align: center; padding: 20px 0; color: #9ca3af; font-size: 14px; line-height: 1.5; border-top: 1px solid #e5e7eb;\">\n"
            +
            "                            <p style=\"margin: 0 0 10px;\">\n" +
            "                                Didn't request this? No worries! Someone else might have accidentally used your email.\n"
            +
            "                            </p>\n" +
            "                            <p style=\"margin: 0;\">\n" +
            "                                <strong>AuthX</strong> • The secure authentication platform<br>\n" +
            "                                <a href=\"https://authx.com\" style=\"color: #6366f1;\">authx.com</a> | \n"
            +
            "                                <a href=\"mailto:support@authx.com\" style=\"color: #6366f1;\">support@authx.com</a>\n"
            +
            "                            </p>\n" +
            "                        </td>\n" +
            "                    </tr>\n" +
            "                </table>\n" +
            "            </td>\n" +
            "        </tr>\n" +
            "    </table>\n" +
            "</body>\n" +
            "</html>\n";

    public static final String PASSWORD_RESET_EMAIL = "<!DOCTYPE html>\n" +
            "<html>\n" +
            "<head>\n" +
            "    <meta charset=\"UTF-8\">\n" +
            "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n" +
            "    <title>Password Reset - AuthX</title>\n" +
            "</head>\n" +
            "<body style=\"margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #f8f9fa;\">\n"
            +
            "    <table role=\"presentation\" width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" border=\"0\" style=\"background-color: #f8f9fa;\">\n"
            +
            "        <tr>\n" +
            "            <td style=\"padding: 40px 20px 20px;\">\n" +
            "                <table role=\"presentation\" align=\"center\" width=\"600\" cellspacing=\"0\" cellpadding=\"0\" border=\"0\">\n"
            +
            "                    <tr>\n" +
            "                        <td style=\"text-align: center; padding-bottom: 20px;\">\n" +
            "                            <h1 style=\"margin: 0; font-size: 28px; font-weight: 700; color: #1a1a1a;\">Reset your password on <span style=\"color: #6366f1;\">AuthX</span></h1>\n"
            +
            "                        </td>\n" +
            "                    </tr>\n" +
            "                </table>\n" +
            "            </td>\n" +
            "        </tr>\n" +
            "        <tr>\n" +
            "            <td style=\"padding: 0 20px 40px;\">\n" +
            "                <table role=\"presentation\" align=\"center\" width=\"600\" cellspacing=\"0\" cellpadding=\"0\" border=\"0\" style=\"background-color: white; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.08);\">\n"
            +
            "                    <tr>\n" +
            "                        <td style=\"padding: 60px 50px 40px;\">\n" +
            "                            <h2 style=\"margin: 0 0 20px; font-size: 24px; font-weight: 600; color: #1a1a1a;\">Reset your password</h2>\n"
            +
            "                            <p style=\"margin: 0 0 30px; font-size: 16px; line-height: 1.6; color: #4b5563;\">\n"
            +
            "                                Hi <strong>${username}</strong>,<br><br>\n" +
            "                                We received a request to reset your account password. Click the button below to create a new password for your <strong>AuthX</strong> account.\n"
            +
            "                            </p>\n" +
            "                            <table role=\"presentation\" align=\"center\" width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" border=\"0\">\n"
            +
            "                                <tr>\n" +
            "                                    <td style=\"text-align: center; padding: 30px 0;\">\n" +
            "                                        <a href=\"${resetUrl}\" style=\"display: inline-block; padding: 16px 40px; background-color: #6366f1; color: white; text-decoration: none; font-size: 16px; font-weight: 600; border-radius: 8px; box-shadow: 0 4px 12px rgba(99, 102, 241, 0.3); transition: all 0.2s;\">\n"
            +
            "                                            Reset Password\n" +
            "                                        </a>\n" +
            "                                    </td>\n" +
            "                                </tr>\n" +
            "                            </table>\n" +
            "                            <p style=\"margin: 30px 0 0; font-size: 14px; line-height: 1.6; color: #6b7280; text-align: center;\">\n"
            +
            "                                Or copy and paste this link into your browser:<br>\n" +
            "                                <a href=\"${resetUrl}\" style=\"color: #6366f1; word-break: break-all;\">${resetUrl}</a>\n"
            +
            "                            </p>\n" +
            "                            <p style=\"margin: 40px 0 0; font-size: 14px; color: #6b7280;\">\n" +
            "                                If you did not request this, you can safely ignore this email. Your password will remain unchanged.\n"
            +
            "                            </p>\n" +
            "                        </td>\n" +
            "                    </tr>\n" +
            "                </table>\n" +
            "            </td>\n" +
            "        </tr>\n" +
            "        <tr>\n" +
            "            <td style=\"padding: 40px 20px;\">\n" +
            "                <table role=\"presentation\" align=\"center\" width=\"600\" cellspacing=\"0\" cellpadding=\"0\" border=\"0\">\n"
            +
            "                    <tr>\n" +
            "                        <td style=\"text-align: center; padding: 20px 0; color: #9ca3af; font-size: 14px; line-height: 1.5; border-top: 1px solid #e5e7eb;\">\n"
            +
            "                            <p style=\"margin: 0 0 10px;\">Need help? Our support team is here for you.</p>\n"
            +
            "                            <p style=\"margin: 0;\"><strong>AuthX</strong> • The secure authentication platform<br><a href=\"https://authx.com\" style=\"color: #6366f1;\">authx.com</a> | <a href=\"mailto:support@authx.com\" style=\"color: #6366f1;\">support@authx.com</a></p>\n"
            +
            "                        </td>\n" +
            "                    </tr>\n" +
            "                </table>\n" +
            "            </td>\n" +
            "        </tr>\n" +
            "    </table>\n" +
            "</body>\n" +
            "</html>\n";
}