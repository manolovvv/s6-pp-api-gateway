package com.gateway.conf;

import com.gateway.security.JwtAuthenticationEntryPoint;
import com.gateway.security.JwtRequestFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    @Autowired
    private UserDetailsService jwtUserDetailsService;

    @Autowired
    private JwtRequestFilter jwtRequestFilter;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CorsFilter corsFilter() {
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        final CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.addAllowedOrigin("*");
        config.addAllowedHeader("*");
        config.addAllowedMethod("OPTIONS");
        config.addAllowedMethod("HEAD");
        config.addAllowedMethod("GET");
        config.addAllowedMethod("POST");
        config.addAllowedMethod("DELETE");
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }

    @Override
    public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        // configure AuthenticationManager so that it knows from where to load
        // user for matching credentials
        // Use BCryptPasswordEncoder
        authenticationManagerBuilder.userDetailsService(jwtUserDetailsService).passwordEncoder(passwordEncoder());

    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {

        // We don't need CSRF for this example
        httpSecurity.csrf().disable()
                .authorizeRequests()
                // Blacklisted routes
                .antMatchers(HttpMethod.POST,"/api/post-service/*").access("hasAuthority('USER')")
                .antMatchers(HttpMethod.DELETE,"/api/post-service/deletepost/*").access("hasAuthority('ADMIN')")
                .antMatchers(HttpMethod.POST,"/api/post-service/addcomment/*").access("hasAuthority('USER')")
                .antMatchers(HttpMethod.DELETE,"/api/post-service/deletecomment/*").access("hasAuthority('ADMIN')")
                .antMatchers(HttpMethod.DELETE,"/api/user-details-service/*").access("hasAuthority('USER')")
                .antMatchers("/api/auth-service/getpost/*").authenticated()
                .antMatchers(HttpMethod.GET,"/api/user-details-service/*").authenticated()
                .antMatchers("/api/auth-service/getbycategory/*").authenticated()
                .antMatchers(HttpMethod.GET,"/api/post-service/").authenticated()

                // Whitelisted routes
                .antMatchers("/api/auth-service/*").permitAll()
                .antMatchers(HttpMethod.POST,"/api/user-details-service/").permitAll().and().

                // make sure we use stateless session; session won't be used to
                // store user's state.
                        exceptionHandling().authenticationEntryPoint(jwtAuthenticationEntryPoint).and().sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        // Add a filter to validate the tokens with every request
        httpSecurity.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
