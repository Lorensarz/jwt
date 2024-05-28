package com.petrov.jwt.service;


import com.petrov.jwt.model.User;

import java.util.List;



public interface UserService {

    User register(User user);

    List<User> getAll();

    User findByUsername(String username);

    User findById(Long id);

    void delete(Long id);

    void increaseFailedAttempts(User user);

    void resetFailedAttempts(String username);

    void lock(User user);

    boolean unlockWhenTimeExpired(User user);
}
