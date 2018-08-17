package com.company.springbootsecurityjpa.utils;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class EncryptedPasswordUtils {

    //encryte password with BCryptPasswordEncoder
    public static String encrytePassword(String password){
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        return encoder.encode(password);
    }

    public static void main(String[] args) {
        String password = "123";
        String encryptedPassword = encrytePassword(password);

        System.out.println("Encrypted Password: "+encryptedPassword);
    }
}
