package com.oauth.server.uaa.services;


import com.oauth.server.uaa.entities.UserEntity;
import com.oauth.server.uaa.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService implements UserDetailsService {

	@Autowired
	private UserRepository repository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		
		Optional<UserEntity> user = repository.findByUsername(username);
		if (!user.isPresent()) {
			throw new UsernameNotFoundException("User not found");
		}
		return user.get();
	}
}
