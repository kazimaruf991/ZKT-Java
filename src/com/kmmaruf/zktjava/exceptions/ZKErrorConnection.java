package com.kmmaruf.zktjava.exceptions;

public class ZKErrorConnection extends ZKError{
    public ZKErrorConnection() {
        super();
    }

    public ZKErrorConnection(String message) {
        super(message);
    }

    public ZKErrorConnection(String message, Throwable cause) {
        super(message, cause);
    }
}
