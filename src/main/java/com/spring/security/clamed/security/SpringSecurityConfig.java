package com.spring.security.clamed.security;

import com.spring.security.clamed.services.UsuarioService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.WebSecurity;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UsuarioService usuarioService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                //quais requisicoes serao autorizadas e como sera a autorizacao
                .authorizeRequests()
                /* quais URLS vamos filtrar? é para permitir ou para bloquear?
                o método antMatches tem 3 sobrecargas
                1- passa somente a URL
                2- passa somente o método GET, POST, PUT, DELETE...
                3- passando o método http e a URL (estamos usando esse)
                */
                .antMatchers(HttpMethod.GET,"usuarios")
                //permite todos os acessos
                .permitAll()
                .antMatchers("/usuarios/**").hasRole("ADMINISTRADOR")
                //de qualquer requisição
                .anyRequest()
                // aceitar somente requisições autenticadas
                .authenticated()
                .and()
                /*CSRF é um tipo de ataque a aplicações web. Porem como a autenticação sera feito por token
                a proteção a esse ataque é dispensável*/
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                /*Filtrar as requisições de login para fazer autenticação*/
                .addFilterBefore(new JwtLoginFilter("/login", authenticationManager()),
                        UsernamePasswordAuthenticationFilter.class)

                /* Filtrar as demais requisições para verificar a preservação do token JWT no header do HTTP */
                .addFilterBefore(new JwtApiAutenticaoFilter(), UsernamePasswordAuthenticationFilter.class);

                @Override
                protected void configure(AuthenticationManagerBuilder auth) throws Exception {
                    // Service que irá consultar o usuário no banco de dados
                    auth.userDetailsService(usuarioService)

                            // definir a codificação de senha
                            .passwordEncoder(new BCryptPasswordEncoder());

                }

                @Override
                public void configure(WebSecurity web) throws Exception {
                    // configura URLs para não passar pelos filtros de segurança
                    web.ignoring().antMatchers("/**.html",
                            "/v2/api-docs",
                            "/webjars/**");
                }


    }
}
