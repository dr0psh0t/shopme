package com.shopme.admin.config;

import com.shopme.admin.dao.UserRepo;
import com.shopme.admin.entity.User;
import com.shopme.admin.utils.Log;
import org.jboss.aerogear.security.otp.Totp;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class CustomAuthenticationProvider extends DaoAuthenticationProvider {

    private final UserRepo userRepo;

    public CustomAuthenticationProvider(UserRepo userRepo) {
        this.userRepo = userRepo;
    }

    @Override
    public Authentication authenticate(Authentication auth) throws AuthenticationException {

        String verificationCode = ((CustomWebAuthenticationDetails) auth.getDetails()).getVerificationCode();

        User user = userRepo.findByEmail(auth.getName());

        if (user == null) {
            Log.error("No user found with username: "+auth.getName());
            throw new BadCredentialsException("Invalid username or password");
        }

        if (user.isUsing2FA()) {
            Totp totp = new Totp(user.getSecret());

            if (!isValidLong(verificationCode) || !totp.verify(verificationCode)) {
                Log.error("Invalid verfication code: "+verificationCode);
                throw new BadCredentialsException("Invalid verfication code");
            }
        }

        Authentication result = super.authenticate(auth);

        Log.info("Logging in user "+user.getEmail());
        Log.info("Authorities: "+result.getAuthorities());

        return new UsernamePasswordAuthenticationToken(user, result.getCredentials(), result.getAuthorities());
    }

    private boolean isValidLong(String code) {
        try {
            Long.parseLong(code);
        } catch (NumberFormatException e) {
            return false;
        }
        return true;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
