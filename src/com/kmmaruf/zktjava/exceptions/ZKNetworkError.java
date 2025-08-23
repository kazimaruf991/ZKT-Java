package com.kmmaruf.zktjava.exceptions;

public class ZKNetworkError extends ZKError{
    public ZKNetworkError() {
        super();
    }

    public ZKNetworkError(String message) {
        super(message);
    }

    public ZKNetworkError(String message, Throwable cause) {
        super(message, cause);
    }
}
