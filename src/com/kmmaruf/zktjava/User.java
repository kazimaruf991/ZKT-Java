package com.kmmaruf.zktjava;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class User {
    public static final String ENCODING = "UTF-8";

    public int uid;
    public String name;
    public int privilege;
    public String password;
    public String groupId;
    public String userId;
    public long card; // 64-bit input, used as 40-bit

    // Constructor
    public User(int uid, String name, int privilege, String password, String groupId, String userId, long card) {
        this.uid = uid;
        this.name = name;
        this.privilege = privilege;
        this.password = password != null ? password : "";
        this.groupId = groupId != null ? groupId : "";
        this.userId = userId != null ? userId : "";
        this.card = card;
    }

    // JSON unpack
    public static User jsonUnpack(Map<String, Object> json) {
        return new User(
                (int) json.get("uid"),
                (String) json.get("name"),
                (int) json.get("privilege"),
                (String) json.get("password"),
                (String) json.get("group_id"),
                (String) json.get("user_id"),
                ((Number) json.get("card")).longValue()
        );
    }

    // JSON pack
    public Map<String, Object> jsonPack() {
        Map<String, Object> json = new HashMap<>();
        json.put("uid", uid);
        json.put("name", name);
        json.put("privilege", privilege);
        json.put("password", password);
        json.put("group_id", groupId);
        json.put("user_id", userId);
        json.put("card", card);
        return json;
    }

    // repack29: <BHB5s8sIxBhI>
    public byte[] repack29() {
        byte[] pwdBytes = safeEncode(password, 5);
        byte[] nameBytes = safeEncode(name, 8);
        byte[] userIdBytes = safeEncode(userId, 4); // assuming 4 bytes for int
        int group = groupId.isEmpty() ? 0 : Integer.parseInt(groupId);

        ByteBuffer buffer = ByteBuffer.allocate(29);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.put((byte) 2);                  // B
        buffer.putShort((short) uid);          // H
        buffer.putShort((short) privilege);    // H
        buffer.put(pwdBytes);                  // 5s
        buffer.put(nameBytes);                 // 8s
        buffer.putInt((int) card);             // I (lower 32 bits)
        buffer.put((byte) group);              // B
        buffer.put((byte) 0);                  // h (placeholder)
        buffer.putInt(Integer.parseInt(userId)); // I
        return buffer.array();
    }

    // repack73: <BHB8s24sIB7sx24s>
    public byte[] repack73() {
        byte[] pwdBytes = safeEncode(password, 8);
        byte[] nameBytes = safeEncode(name, 24);
        byte[] groupBytes = safeEncode(groupId, 7);
        byte[] userIdBytes = safeEncode(userId, 24);

        ByteBuffer buffer = ByteBuffer.allocate(73);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.put((byte) 2);                  // B
        buffer.putShort((short) uid);          // H
        buffer.putShort((short) privilege);    // H
        buffer.put(pwdBytes);                  // 8s
        buffer.put(nameBytes);                 // 24s
        buffer.putInt((int) card);             // I
        buffer.put((byte) 1);                  // B
        buffer.put(groupBytes);                // 7s
        buffer.put((byte) 0);                  // x (padding)
        buffer.put(userIdBytes);               // 24s
        return buffer.array();
    }

    // Utility: encode string to fixed-size byte array
    private byte[] safeEncode(String value, int length) {
        byte[] raw = new byte[length];
        try {
            byte[] encoded = value.getBytes(ENCODING);
            System.arraycopy(encoded, 0, raw, 0, Math.min(encoded.length, length));
        } catch (Exception e) {
            // Ignore encoding errors
        }
        return raw;
    }

    // Privilege checks
    public boolean isDisabled() {
        return (privilege & 1) != 0;
    }

    public boolean isEnabled() {
        return !isDisabled();
    }

    public int userType() {
        return privilege & 0xE;
    }

    @Override
    public String toString() {
        return String.format("<User>: [uid:%d, name:%s user_id:%s]", uid, name, userId);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof User)) return false;
        User other = (User) obj;
        return uid == other.uid &&
                privilege == other.privilege &&
                card == other.card &&
                Objects.equals(name, other.name) &&
                Objects.equals(password, other.password) &&
                Objects.equals(groupId, other.groupId) &&
                Objects.equals(userId, other.userId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(uid, name, privilege, password, groupId, userId, card);
    }
}