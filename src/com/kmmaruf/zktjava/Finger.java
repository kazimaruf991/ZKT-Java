package com.kmmaruf.zktjava;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class Finger {
    private int size;
    private int uid;
    public int fid;
    private int valid;
    private byte[] template;
    private byte[] mark;

    public Finger(int uid, int fid, int valid, byte[] template) {
        this.size = template.length;
        this.uid = uid;
        this.fid = fid;
        this.valid = valid;
        this.template = template;
        this.mark = buildMark(this.template);
    }

    public byte[] repack() {
        int totalSize = size + 6;

        // Manually split shorts into low/high bytes (little-endian)
        byte[] header = BinUtils.pack(totalSize & 0xFF, (totalSize >> 8) & 0xFF, // size + 6
                uid & 0xFF, (uid >> 8) & 0xFF,             // uid
                fid & 0xFF,                                // fid
                valid & 0xFF                               // valid
        );

        // Combine header + template
        byte[] result = new byte[header.length + template.length];
        System.arraycopy(header, 0, result, 0, header.length);
        System.arraycopy(template, 0, result, header.length, template.length);

        return result;
    }

    public byte[] repack_only() {
        byte[] header = BinUtils.pack(size & 0xFF, (size >> 8) & 0xFF); // Little-endian short

        byte[] result = new byte[header.length + template.length];
        System.arraycopy(header, 0, result, 0, header.length);
        System.arraycopy(template, 0, result, header.length, template.length);

        return result;
    }

    public static Finger json_unpack(Map<String, Object> json) {
        int uid = (int) json.get("uid");
        int fid = (int) json.get("fid");
        int valid = (int) json.get("valid");
        String hexTemplate = (String) json.get("template");

        byte[] template = BinUtils.hexStringToByteArray(hexTemplate);

        return new Finger(uid, fid, valid, template);
    }

    public Map<String, Object> json_pack() {
        Map<String, Object> json = new HashMap<>();
        json.put("size", this.size);
        json.put("uid", this.uid);
        json.put("fid", this.fid);
        json.put("valid", this.valid);
        json.put("template", BinUtils.byteArrayToHex(this.template));
        return json;
    }

    public byte[] buildMark(byte[] template) {
        // Slice first and last 8 bytes
        byte[] head = Arrays.copyOfRange(template, 0, 8);
        byte[] tail = Arrays.copyOfRange(template, template.length - 8, template.length);

        // Convert to hex strings
        String headHex = toHex(head);
        String tailHex = toHex(tail);

        // Concatenate with literal "..." and convert back to bytes
        String markString = headHex + "..." + tailHex;
        return markString.getBytes(); // UTF-8 by default
    }

    private String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b)); // Lowercase hex to match Python's default
        }
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;

        Finger other = (Finger) obj;
        return uid == other.uid && fid == other.fid && size == other.size && valid == other.valid && Arrays.equals(mark, other.mark) && Arrays.equals(template, other.template);
    }

    @Override
    public String toString() {
        return String.format("<Finger> [uid:%3d, fid:%d, size:%4d v:%d t:%s]", uid, fid, size, valid, mark);
    }

    public String dump() {
        return String.format("<Finger> [uid:%3d, fid:%d, size:%4d v:%d t:%s]", uid, fid, size, valid, BinUtils.byteArrayToHex(template));
    }
}
