package com.shopme.admin.config;

import com.shopme.admin.dao.UserRepo;
import com.shopme.admin.entity.Roles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
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
    private final CustomWebAuthenticationDetailsSource authenticationDetailsSource;
    private final UserRepo userRepo;

    public ShopmeBackendSecurityConfig(
            UserDetailsService userDetailsService,
            BCryptPasswordEncoder bCryptPasswordEncoder,
            CustomWebAuthenticationDetailsSource authenticationDetailsSource,
            UserRepo userRepo) {

        this.userDetailsService = userDetailsService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.authenticationDetailsSource = authenticationDetailsSource;
        this.userRepo = userRepo;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
        auth.authenticationProvider(authProvider());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.authorizeRequests()
                .antMatchers("/Login", "/Authenticate").permitAll()

                .antMatchers("/SaveUser", "/AddUserForm", "/UpdateUserForm",
                        "/DeleteUser", "/Enable", "/Disable", "/CsvExport", "/ExcelExport",
                        "/PdfExport").hasAnyAuthority(Roles.Admin.name())

                .antMatchers("/Users", "/Users/**", "/Search", "/GetPhoto", "/AccessDenied",
                        "/ErrorPage", "/GetFile", "/CheckDuplicateEmail", "/SearchKey", "/DeleteUserRest")
                .hasAnyAuthority(Roles.Admin.name(),Roles.Shipper.name(),Roles.Salesperson.name(),
                        Roles.Editor.name(), Roles.Assistant.name())

        .and()
                .formLogin()
                .authenticationDetailsSource(authenticationDetailsSource)
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

    @Bean
    public DaoAuthenticationProvider authProvider() {
        CustomAuthenticationProvider authProvider = new CustomAuthenticationProvider(userRepo);
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(bCryptPasswordEncoder);
        return authProvider;
    }
}