package com.r2playground.service.auth.exception;

public class AuthException extends RuntimeException {

    public AuthException(String message, Throwable t){
        super(message, t);
    }


}
