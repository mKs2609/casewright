package com.securityanalyst.gateway.common;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.net.InetAddress;
import java.util.regex.Pattern;

import jakarta.validation.Constraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import jakarta.validation.Payload;

/**
 * The value must be a written-out IPv4 or IPv6 address, such as 185.220.101.47 or 2001:db8::1.
 *
 * - IPv4: exactly four numbers 0-255, no leading zeros. Old shorthand forms that many
 *   parsers (Java's included) still accept are refused: "185.220.101" (meaning 185.220.0.101),
 *   "3232235777" (one big number), "010.0.0.1" (010 is 8 to some tools, 10 to others). Tools
 *   that read the same text differently are a classic way to slip past filters.
 * - IPv6: parsed with InetAddress.ofLiteral, which only parses and never touches the network
 *   (InetAddress.getByName would look a hostname up in DNS). A "%zone" suffix is refused:
 *   it only means something on the machine that wrote it.
 * Null is allowed here; add @NotNull when the field is required.
 */
@Documented
@Constraint(validatedBy = IpAddress.Validator.class)
@Target({ ElementType.FIELD, ElementType.PARAMETER, ElementType.RECORD_COMPONENT, ElementType.TYPE_USE })
@Retention(RetentionPolicy.RUNTIME)
public @interface IpAddress {

    String message() default "must be an IPv4 or IPv6 address";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    class Validator implements ConstraintValidator<IpAddress, String> {

        private static final String OCTET = "(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])";
        private static final Pattern IPV4 = Pattern.compile("^" + OCTET + "(\\." + OCTET + "){3}$");

        @Override
        public boolean isValid(String value, ConstraintValidatorContext context) {
            if (value == null) {
                return true;
            }
            if (!value.contains(":")) {
                return IPV4.matcher(value).matches();
            }
            if (value.length() > 45 || value.contains("%")) {   // 45: the longest written-out IPv6 address
                return false;
            }
            try {
                InetAddress.ofLiteral(value);
                return true;
            } catch (IllegalArgumentException e) {
                return false;
            }
        }
    }
}
