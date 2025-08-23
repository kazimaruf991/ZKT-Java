package com.kmmaruf.zktjava.exceptions;

public class ZKErrorResponse extends ZKError{
    public ZKErrorResponse() {
        super();
    }

    public ZKErrorResponse(String message) {
        super(message);
    }

    public ZKErrorResponse(String message, Throwable cause) {
        super(message, cause);
    }
}
