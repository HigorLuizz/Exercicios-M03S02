package com.spring.security.clamed.services;

import com.spring.security.clamed.modals.Usuario;
import com.spring.security.clamed.repositories.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class UsuarioService implements UserDetailsService {

    @Autowired
    private UsuarioRepository usuarioRepository;

    public Usuario salvar(Usuario usuario){
        return usuarioRepository.save(usuario);
    }

    @Transactional
    public void delete(Long idUsuario){
        usuarioRepository.deleteById(idUsuario);
    }

    public Usuario getUserById(Long idusuario){
        Usuario usuario = usuarioRepository.findById(idusuario).get();
        return  usuario;
    }

    public List<Usuario> getUsersByName(String nome){
        return usuarioRepository.findUsersByName(nome);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Usuario usuario = usuarioRepository.findUserByLogin(username);
        if (usuario == null){
            throw new UsernameNotFoundException("usuario não encontrado");
        }
        return new User(usuario.getLogin(), usuario.getPassword(), usuario.getAuthorities());
    }

    @Transactional(readOnly = true)
    public List<Usuario> getUsers(){
        List<Usuario> usuarios = usuarioRepository.findAll();

        return usuarios;
    }
}
