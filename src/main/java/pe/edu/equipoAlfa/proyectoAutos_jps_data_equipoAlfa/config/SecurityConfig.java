package pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                // definir rutas protegidas y quien puede acceder a ellas
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/clientes/login").permitAll() // rutas de acceso público
                        .requestMatchers("/clientes/restricted").hasAnyRole("ADMIN", "OPERATOR")// configuración de acceso para ADMIN y OPERATOR
                        .requestMatchers("/clientes/listar").hasAnyRole("ADMIN")
                        .anyRequest().authenticated() // el resto de rutas deben autenticarse
                )
                .exceptionHandling(ex -> ex
                        .accessDeniedHandler((request,
                                              response,
                                              accessDeniedException) -> {
                            response.sendRedirect("/clientes/restricted");
                        })
                )

                // configurar formulario de inicio de sesión
                .formLogin(form -> form
                        .loginPage("/clientes/login")
                        .defaultSuccessUrl("/clientes/restricted", false) //false sirve para que te redireccione a la pagina que querias ingresar antes de logearte
                        .permitAll()
                )

                // configurar salida (logout)
                .logout(logout -> logout
                        .logoutUrl("/clientes/logout")
                        .logoutSuccessUrl("/clientes/login?logout")
                        .permitAll()
                );
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> User.builder()
                .username("Patricio")
                .password(passwordEncoder().encode("123456"))
                .roles("ADMIN")
                .build();
    }


}
