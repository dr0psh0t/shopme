package com.shopme.admin.config;

import com.shopme.admin.entity.Roles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
public class ShopmeBackendSecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public ShopmeBackendSecurityConfig(
            UserDetailsService userDetailsService, BCryptPasswordEncoder bCryptPasswordEncoder) {

        this.userDetailsService = userDetailsService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth)
            throws Exception {

        auth.userDetailsService(userDetailsService)
                .passwordEncoder(bCryptPasswordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.authorizeRequests()
                .antMatchers("/Login").permitAll()

                .antMatchers("/SaveUser", "/AddUserForm", "/UpdateUserForm",
                        "/DeleteUser", "/Enable", "/Disable", "/CsvExport", "/ExcelExport",
                        "/PdfExport").hasAnyAuthority(Roles.Admin.name())

                .antMatchers("/Users", "/Users/**", "/Search", "/GetPhoto", "/AccessDenied",
                        "/ErrorPage", "/GetFile", "/CheckDuplicateEmail", "/SearchKey", "/DeleteUserRest")
                .hasAnyAuthority(Roles.Admin.name(),Roles.Shipper.name(),Roles.Salesperson.name(),
                        Roles.Editor.name(), Roles.Assistant.name())

        .and()
                .formLogin()
                .loginPage("/Login")
                .loginProcessingUrl("/authenticateTheUser")
                .defaultSuccessUrl("/")
                .permitAll()
                .and()
                .logout()
                .logoutUrl("/Logout")
                .invalidateHttpSession(true)
                .permitAll()	//	adds logout support
                .and()
                .exceptionHandling().accessDeniedPage("/AccessDenied");
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean()
            throws Exception {
        return super.authenticationManagerBean();
    }
}