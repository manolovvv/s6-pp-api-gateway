package com.gateway.security;

import com.gateway.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

@Service
public class JwtUserDetailsService implements UserDetailsService {

    @Autowired
    private WebClient.Builder webClientBuilder;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        String url = String.format("http://10.108.15.50:8081/getOneByEmail/%s",email);
        User user = webClientBuilder
                .build()
                .get()
                .uri(url)
                .retrieve()
                .bodyToMono(User.class)
                .block();
        if(user == null){
            throw new UsernameNotFoundException("User not found");
        }
        return JwtUserDetailsImpl.build(user);
    }

}
