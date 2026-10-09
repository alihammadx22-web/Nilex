package com.nilex.grad.exception;

public class GoogleAccountConflictException extends RuntimeException {

    public GoogleAccountConflictException() {
        super("This email already belongs to another account");
    }
}
