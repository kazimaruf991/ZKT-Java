package com.kmmaruf.zktjava.exceptions;

public class ZKError extends Exception{
    public ZKError() {
        super();
    }

    public ZKError(String message) {
        super(message);
    }

    public ZKError(String message, Throwable cause) {
        super(message, cause);
    }
}
