package com.kmmaruf.zktjava;

public class BinUtils {
    // Pack any number of integers (0–255) into a byte array
    public static byte[] pack(int... values) {
        byte[] result = new byte[values.length];
        for (int i = 0; i < values.length; i++) {
            result[i] = (byte)(values[i] & 0xFF);
        }
        return result;
    }

    // Unpack a byte array into unsigned integers
    public static int[] unpack(byte[] data) {
        int[] result = new int[data.length];
        for (int i = 0; i < data.length; i++) {
            result[i] = data[i] & 0xFF;
        }
        return result;
    }

    public static String byteArrayToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    // Packs an int into 4 bytes (little-endian)
    public static byte[] packIntLE(int value) {
        return new byte[] {
                (byte) (value & 0xFF),
                (byte) ((value >> 8) & 0xFF),
                (byte) ((value >> 16) & 0xFF),
                (byte) ((value >> 24) & 0xFF)
        };
    }

    // Unpacks a short from 2 bytes (little-endian)
    public static short unpackShortLE(byte[] data, int offset) {
        return (short) ((data[offset] & 0xFF) | ((data[offset + 1] & 0xFF) << 8));
    }

    // Packs two shorts into 4 bytes (little-endian)
    public static byte[] packShortLE(short s1, short s2) {
        return new byte[] {
                (byte) (s1 & 0xFF),
                (byte) ((s1 >> 8) & 0xFF),
                (byte) (s2 & 0xFF),
                (byte) ((s2 >> 8) & 0xFF)
        };
    }
}
