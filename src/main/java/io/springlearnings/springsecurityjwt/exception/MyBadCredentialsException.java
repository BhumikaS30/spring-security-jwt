package io.springlearnings.springsecurityjwt.exception;

public class MyBadCredentialsException extends Exception {
    public MyBadCredentialsException(String message) {
        super(message);
    }
}
