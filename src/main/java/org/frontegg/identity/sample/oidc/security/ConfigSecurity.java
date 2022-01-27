package org.frontegg.identity.sample.oidc.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.net.URI;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Class that handles basic security configurations.
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(
        prePostEnabled = true,
        securedEnabled = true)
//        jsr250Enabled = true, proxyTargetClass = true)
public class ConfigSecurity extends WebSecurityConfigurerAdapter {

    @Value("${client.post-logout-uri}")
    private String postLogoutUri;

    private static final String ROLES_CLAIM = "roles";

    /**
     * Configure the spring-security with default login page as /login and logout url as '/applogout'. All the other
     * endpoints of the application are secured.
     *
     * @param http
     * @throws Exception
     */
    protected void configure(HttpSecurity http) throws Exception {

        http.authorizeRequests()
                .antMatchers("/login","/css/*", "/images/*")
                .permitAll()

                .anyRequest()
                .authenticated()
                .and()
                .exceptionHandling().accessDeniedPage("/403")
                .and()
                .oauth2Login()
                .loginPage("/login")
                .and()
                .logout().logoutUrl("/logout")
                .logoutSuccessHandler(oidcLogoutSuccessHandler());
    }

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    /**
     * Handles OIDC Logout redirection.
     *
     * @return LogoutSuccessHandler
     */
    private LogoutSuccessHandler oidcLogoutSuccessHandler() {

        OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler = new OidcClientInitiatedLogoutSuccessHandler(
                this.clientRegistrationRepository);
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri(URI.create(postLogoutUri));
        return oidcLogoutSuccessHandler;
    }

    @Bean
    @SuppressWarnings({"unchecked", "java:S5411"})
    GrantedAuthoritiesMapper userAuthoritiesMapper() {
        return authorities -> {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();
            var authority = authorities.iterator().next();
            boolean isOidc = authority instanceof OidcUserAuthority;

//            if (isOidc) {
//                var oidcUserAuthority = (OidcUserAuthority) authority;
//                var userInfo = oidcUserAuthority.getUserInfo();
//
//                if (userInfo.containsClaim(ROLES_CLAIM)) {
//                    var roles = userInfo.getClaimAsStringList(ROLES_CLAIM);
//                    mappedAuthorities.addAll(generateAuthoritiesFromClaim(roles));
//                }
//            } else {
                var oauth2UserAuthority = (OAuth2UserAuthority) authority;
                Map<String, Object> userAttributes = oauth2UserAuthority.getAttributes();

                if (userAttributes.containsKey(ROLES_CLAIM)) {
                    var roles = (Collection<String>) userAttributes.get(ROLES_CLAIM);
                    mappedAuthorities.addAll(generateAuthoritiesFromClaim(roles));
                }
//            }

            return mappedAuthorities;
        };

    }

    Collection<GrantedAuthority> generateAuthoritiesFromClaim(Collection<String> roles) {
            return roles.stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                    .collect(Collectors.toList());
    }

}
