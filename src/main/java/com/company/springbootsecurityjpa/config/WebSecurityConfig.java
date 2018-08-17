package com.company.springbootsecurityjpa.config;


import com.company.springbootsecurityjpa.service.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Qualifier("dataSource")
    @Autowired
    private DataSource dataSource;

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        return bCryptPasswordEncoder;
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {

        //setting service to find User in the database
        //and setting passwordEncoder
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }


    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();

        //the pages does not require login
        http.authorizeRequests().antMatchers("/", "/login", "/logout").permitAll();

        //userInfo page requires login as ROLE_USER or ROLE_ADMIN
        //if no login, it will redirect to /login page
        http.authorizeRequests().antMatchers("/userInfo").access("hasAnyRole('ROLE_USER','ROLE_ADMIN')");

        //for admin only
        http.authorizeRequests().antMatchers("/admin").access("hasRole('ROLE_ADMIN')");
        //when user has logged in as XX
        //but access a page that requires role YY,
        //AccessDeniedException will be thrown
        http.authorizeRequests().and().exceptionHandling().accessDeniedPage("/403");

        //config for login form
        http.authorizeRequests().and().formLogin()
                //submit url of login page
                .loginProcessingUrl("/j_spring_security_check") // submit url
                .loginPage("/login")
                .defaultSuccessUrl("/userAccountInfo")
                .failureUrl("/login?error=true")
                .usernameParameter("username")
                .passwordParameter("password")
                //config for logout page
                .and().logout().logoutUrl("/logout").logoutSuccessUrl("/logoutSuccessful");

        //config remember me
        http.authorizeRequests().and()
                .rememberMe().tokenRepository(this.persistentTokenRepository())
                .tokenValiditySeconds(1 * 24 * 60 * 60); //24h


    }

    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl db = new JdbcTokenRepositoryImpl();
        db.setDataSource(dataSource);
        return db;
    }


}
