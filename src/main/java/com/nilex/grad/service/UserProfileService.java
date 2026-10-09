package com.nilex.grad.service;

import com.nilex.grad.dto.UserProfileResponse;
import com.nilex.grad.model.User;
import com.nilex.grad.repository.UserRepository;

import com.nilex.grad.exception.InvalidCredentialsException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserProfileService {

    private final UserRepository userRepository;

    @Transactional(readOnly = true)
    public UserProfileResponse getProfile(UUID authenticatedUserId) {
        User user = userRepository.findById(authenticatedUserId)
                .filter(User::isActive)
                .orElseThrow(InvalidCredentialsException::new);
        return UserProfileResponse.from(user);
    }
}
