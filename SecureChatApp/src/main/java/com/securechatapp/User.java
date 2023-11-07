package com.securechatapp;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 *
 * @author Alex
 */
public class User {
    private String username;
    private String password; // Hashed and salted
    private PublicKey publicKey;
    private PrivateKey privateKey;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public User(String username, String password, PublicKey publicKey, PrivateKey privateKey) {
        this.username = username;
        this.password = password;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }
}
