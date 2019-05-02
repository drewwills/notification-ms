package uk.ac.ed.notify.config;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * Configures support for HTTP BASIC AuthN (in tandem with OAuth).  See
 * https://stackoverflow.com/questions/23526644/spring-security-with-oauth2-or-http-basic-authentication-for-the-same-resource
 * for more information about this solution.
 */
@Configuration
@Order(2)
@EnableWebSecurity
public class BasicAuthConfiguration extends WebSecurityConfigurerAdapter {

    public static final String NOTIFICATION_API_UI = "notification-api-ui";

    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * Username for the 'notification-ui' (service) user for use with HTTP BASIC AuthN.
     */
    @Value("${uk.ac.ed.notify.security.basicAuthUsername:notification-ui}")
    private String basicAuthUsername;

    /**
     * Password for the 'notification-ui' (service) user for use with HTTP BASIC AuthN.
     */
    @Value("${uk.ac.ed.notify.security.basicAuthPassword:}")
    private String basicAuthPassword;

    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
        final InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder> config = auth.inMemoryAuthentication();
        /*
         * Configure HTTP BASIC AuthN if (and only if) a password is specified
         */
        if (StringUtils.isNotBlank(basicAuthPassword)) {
            config
                    .withUser(basicAuthUsername)
                    .password(basicAuthPassword)
                    .authorities("notification.read", "notification.write");
            logger.info("Supporting HTTP BASIC AuthN to communicate with notification-ms (because " +
                    "uk.ac.ed.notify.security.basicAuthPassword was specified)");
        }
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.anonymous().disable()
                .requestMatcher(request -> {
                    String auth = request.getHeader(HttpHeaders.AUTHORIZATION);
                    return (auth != null && auth.startsWith("Basic"));
                })
                .antMatcher("/**")
                .authorizeRequests()
                // Anyone may access the Swagger UI
                .antMatchers("/", "/lib/*", "/images/*", "/css/*", "/swagger-ui.js","/redoc.html","/swagger-ui.min.js","/swagger-resources","/swagger-resources/*" ,"/v2/api-docs", "/fonts/*", "/v2/api-docs/*", "/api-docs/default/*", "/o2c.html","index.html","/webjars/**","/hystrix/**","/hystrix.stream","/proxy.stream","/healthcheck","/providers","/provider/**").permitAll()
                // APIs require the proper authority
                .antMatchers(HttpMethod.GET, "/notification/**").access("hasAuthority('notification.read')")
                .antMatchers(HttpMethod.GET, "/notifications/**").access("hasAuthority('notification.read')")
                .antMatchers(HttpMethod.POST, "/notification/**").access("hasAuthority('notification.write')")
                .antMatchers(HttpMethod.PUT, "/notification/**").access("hasAuthority('notification.write')")
                .antMatchers(HttpMethod.DELETE, "/notification/**").access("hasAuthority('notification.write')")
                .antMatchers(HttpMethod.GET, "/usernotifications/**").access("hasAuthority('notification.read')")
                .antMatchers(HttpMethod.GET, "/emergencynotifications").access("hasAuthority('notification.read')")
                .antMatchers(HttpMethod.GET, "/push-subscription").access("hasAuthority('notification.read')")
                .and()
                .httpBasic();
    }

}
