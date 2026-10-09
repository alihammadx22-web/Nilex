package com.nilex.grad.exception;

public class InvalidCredentialsException extends RuntimeException {

    public InvalidCredentialsException() {
        super("Authentication is required or the supplied credentials are invalid");
    }
}
