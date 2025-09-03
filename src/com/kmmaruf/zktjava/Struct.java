package com.kmmaruf.zktjava;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

public class Struct {

    public static byte[] pack(String format, Object... values) {
        ParsedFormat pf = parseFormat(format);
        ByteBuffer buf = ByteBuffer.allocate(pf.size).order(pf.byteOrder);
        int vi = 0;

        for (FmtToken tok : pf.tokens) {
            for (int i = 0; i < tok.count; i++) {
                switch (tok.type) {
                    case 'B': // unsigned byte
                        buf.put((byte) ((int) values[vi++])); // mask not needed here, but assumed input is 0–255
                        break;
                    case 'b': // signed byte
                        buf.put(((Number) values[vi++]).byteValue());
                        break;
                    case 'H': // unsigned short
                        buf.putShort((short) ((int) values[vi++])); // assumes input is 0–65535
                        break;
                    case 'h': // signed short
                        buf.putShort(((Number) values[vi++]).shortValue());
                        break;
                    case 'I': // unsigned int
                        buf.putInt((int) values[vi++]); // assumes input is 0–4294967295
                        break;
                    case 'i': // signed int
                        buf.putInt(((Number) values[vi++]).intValue()); break;
                    case 's': {
                        byte[] src = (byte[]) values[vi++];
                        byte[] out = new byte[tok.count];
                        System.arraycopy(src, 0, out, 0, Math.min(src.length, tok.count));
                        buf.put(out);
                        i = tok.count - 1;
                        break;
                    }
                    case 'x':
                        buf.put((byte) 0);
                        break;
                    default:
                        throw new IllegalArgumentException("Unsupported type: " + tok.type);
                }
            }
        } return buf.array();
    }

    public static Object[] unpack(String format, byte[] data) {
        ParsedFormat pf = parseFormat(format);
        ByteBuffer buf = ByteBuffer.wrap(data).order(pf.byteOrder);
        List<Object> out = new ArrayList<>();

        for (FmtToken tok : pf.tokens) {
            for (int i = 0; i < tok.count; i++) {
                switch (tok.type) {
                    case 'B':
                        out.add(buf.get() & 0xFF); // unsigned byte
                        break;
                    case 'b':
                        out.add(buf.get()); // signed byte
                        break;
                    case 'H':
                        out.add(buf.getShort() & 0xFFFF); // unsigned short
                        break;
                    case 'h':
                        out.add(buf.getShort()); // unsigned short
                        break;
                    case 'I':
                        out.add(buf.getInt()); // unsigned int (Java int range)
                        break;
                    case 'i':
                        out.add(buf.getInt()); // signed int
                        break;
                    case 's': {
                        byte[] str = new byte[tok.count];
                        buf.get(str);
                        out.add(str);
                        i = tok.count - 1; // skip remaining iterations
                        break;
                    }
                    case 'x':
                        buf.get(); // skip padding byte
                        break;
                    default:
                        throw new IllegalArgumentException("Unsupported type: " + tok.type);
                }
            }
        }
        return out.toArray();
    }

    private static ParsedFormat parseFormat(String format) {
        if (format.isEmpty()) throw new IllegalArgumentException("Empty format");
        ParsedFormat pf = new ParsedFormat();

        int pos = 0;
        char first = format.charAt(0);
        if (first == '<') {
            pf.byteOrder = ByteOrder.LITTLE_ENDIAN;
            pos++;
        } else if (first == '>') {
            pf.byteOrder = ByteOrder.BIG_ENDIAN;
            pos++;
        } else if (first == '=') {
            pf.byteOrder = ByteOrder.nativeOrder();
            pos++;
        } else {
            pf.byteOrder = ByteOrder.LITTLE_ENDIAN;
        }

        while (pos < format.length()) {
            int count = 0;
            while (pos < format.length() && Character.isDigit(format.charAt(pos))) {
                count = count * 10 + (format.charAt(pos) - '0');
                pos++;
            }
            if (count == 0) count = 1;

            if (pos >= format.length()) throw new IllegalArgumentException("Incomplete format");
            char type = format.charAt(pos++);

            pf.tokens.add(new FmtToken(type, count));
            switch (type) {
                case 'B':
                    pf.size += count;
                    break;
                case 'b':
                    pf.size += count;
                    break;
                case 'H':
                    pf.size += 2 * count;
                    break;
                case 'h':
                    pf.size += 2 * count;
                    break;
                case 'I':
                    pf.size += 4 * count;
                    break;
                case 'i':
                    pf.size += 4 * count;
                    break;
                case 's':
                    pf.size += count;
                    break;
                case 'x':
                    pf.size += count;
                    break;
                default:
                    throw new IllegalArgumentException("Unknown format char: " + type);
            }
        }
        return pf;
    }

    private static class ParsedFormat {
        ByteOrder byteOrder;
        List<FmtToken> tokens = new ArrayList<>();
        int size = 0;
    }

    private static class FmtToken {
        char type;
        int count;

        FmtToken(char t, int c) {
            type = t;
            count = c;
        }
    }

    // Quick test
    public static void main(String[] args) throws Exception {
        byte[] packed = Struct.pack("<4H", 0x1234, 0, 0x5678, 0x9ABC);
        System.out.println(bytesToHex(packed));

        Object[] unpacked = Struct.unpack("<4H", packed);
        for (Object o : unpacked) System.out.println(o);

        byte[] packed2 = Struct.pack("HB8s24s4sx7sx24s", 1, 5, "password".getBytes("UTF-8"), "namePad____________________".getBytes("UTF-8"), "card".getBytes("UTF-8"), "groupId".getBytes("UTF-8"), "userId".getBytes("UTF-8"));
        System.out.println(bytesToHex(packed2));

        Object[] unpacked2 = Struct.unpack("HB8s24s4sx7sx24s", packed2);
        for (Object o : unpacked2) {
            if (o instanceof byte[]) System.out.println(new String((byte[]) o).trim());
            else System.out.println(o);
        }
    }

    private static String bytesToHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) sb.append(String.format("%02X ", b));
        return sb.toString();
    }
}