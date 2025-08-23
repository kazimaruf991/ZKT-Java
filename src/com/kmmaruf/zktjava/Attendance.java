package com.kmmaruf.zktjava;

import java.util.Date;

public class Attendance {
    private int uid;
    private String user_id;
    private Date timestamp;
    private int status;
    private int punch;

    public Attendance(int uid, String user_id, Date timestamp, int status, int punch) {
        this.uid = uid;
        this.user_id = user_id;
        this.timestamp = timestamp;
        this.status = status;
        this.punch = punch;
    }

    public int getUid() {
        return uid;
    }

    public void setUid(int uid) {
        this.uid = uid;
    }

    public String getUser_id() {
        return user_id;
    }

    public void setUser_id(String user_id) {
        this.user_id = user_id;
    }

    public Date getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Date timestamp) {
        this.timestamp = timestamp;
    }

    public int getStatus() {
        return status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public int getPunch() {
        return punch;
    }

    public void setPunch(int punch) {
        this.punch = punch;
    }
}
