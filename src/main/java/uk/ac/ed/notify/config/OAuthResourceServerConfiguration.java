package uk.ac.ed.notify.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

/**
 * Configures support for OAuth2.
 */
@Configuration
@EnableResourceServer
public class OAuthResourceServerConfiguration extends ResourceServerConfigurerAdapter {

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) {
        resources.resourceId("notification");
    }

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true); // you USUALLY want this
        config.addAllowedOrigin("*");
        config.addAllowedHeader("*");
        config.addAllowedMethod("GET");
        config.addAllowedMethod("POST");
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {

        http
                /*
                 * Use SessionCreationPolicy.STATELESS so that "Spring Security will never create an
                 * HttpSession and it will never use it to obtain the SecurityContext."  This
                 * approach means that every request needs to carry authentication.
                 */
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()

                /*
                 * Disable CSRF (not appropriate for a collection of REST APIs that handle security
                 * on each request)
                 */
                .csrf().disable()

                /*
                 * Set up the CorsFilter
                 */
                .addFilterBefore(corsFilter(), ChannelProcessingFilter.class)

                /*
                 * Endpoint security
                 */
                .authorizeRequests()
                // Anyone may access the Swagger UI
                .antMatchers("/", "/lib/*", "/images/*", "/css/*", "/swagger-ui.js","/redoc.html","/swagger-ui.min.js","/swagger-resources","/swagger-resources/*" ,"/v2/api-docs", "/fonts/*", "/v2/api-docs/*", "/api-docs/default/*", "/o2c.html","index.html","/webjars/**","/hystrix/**","/hystrix.stream","/proxy.stream","/healthcheck","/providers","/provider/**").permitAll()
                // APIs require the proper authority
                .antMatchers(HttpMethod.GET, "/notification/**").access("#oauth2.hasScope('notification.read')")
                .antMatchers(HttpMethod.GET, "/notifications/**").access("#oauth2.hasScope('notification.read')")
                .antMatchers(HttpMethod.POST, "/notification/**").access("#oauth2.hasScope('notification.write')")
                .antMatchers(HttpMethod.PUT, "/notification/**").access("#oauth2.hasScope('notification.write')")
                .antMatchers(HttpMethod.DELETE, "/notification/**").access("#oauth2.hasScope('notification.write')")
                .antMatchers(HttpMethod.GET, "/usernotifications/**").access("#oauth2.hasScope('notification.read')")
                .antMatchers(HttpMethod.GET, "/emergencynotifications").access("#oauth2.hasScope('notification.read')")
                .antMatchers(HttpMethod.GET, "/push-subscription").access("#oauth2.hasScope('notification.read')")
                // And other requests require authentication
                .anyRequest().authenticated();

    }

}
