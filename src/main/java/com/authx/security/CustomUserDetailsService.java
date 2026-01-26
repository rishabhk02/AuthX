package com.authx.security;

import com.authx.entity.Permission;
import com.authx.entity.Role;
import com.authx.entity.User;
import com.authx.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + username));

        Set<SimpleGrantedAuthority> authorities = new HashSet<>();

        if (user.getRoles() != null) {
            authorities.addAll(user.getRoles().stream()
                    .map(Role::getName)
                    .map(rn -> new SimpleGrantedAuthority("ROLE_" + rn))
                    .collect(Collectors.toSet()));
        }

        if (user.getUserPermissions() != null) {
            authorities.addAll(user.getUserPermissions().stream()
                    .map(Permission::getName)
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toSet()));
        }

        return new UserPrincipal(user.getId(), user.getEmail(), user.getEnabled(), authorities);
    }
}
