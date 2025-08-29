package com.kmmaruf.zktjava;

public class DeviceConstants {

    // Maximum value for unsigned short
    public static final int USHRT_MAX = 65535;

    // Command codes for device communication
    public static final int CMD_DB_RRQ = 7;           // Read data from the machine
    public static final int CMD_USER_WRQ = 8;         // Upload user info (PC → terminal)
    public static final int CMD_USERTEMP_RRQ = 9;     // Read fingerprint template or similar data
    public static final int CMD_USERTEMP_WRQ = 10;    // Upload fingerprint template
    public static final int CMD_OPTIONS_RRQ = 11;     // Read machine configuration
    public static final int CMD_OPTIONS_WRQ = 12;     // Set machine configuration
    public static final int CMD_ATTLOG_RRQ = 13;      // Read all attendance records
    public static final int CMD_CLEAR_DATA = 14;      // Clear all data
    public static final int CMD_CLEAR_ATTLOG = 15;    // Clear attendance records
    public static final int CMD_DELETE_USER = 18;     // Delete user
    public static final int CMD_DELETE_USERTEMP = 19; // Delete fingerprint template
    public static final int CMD_CLEAR_ADMIN = 20;     // Cancel manager privileges
    public static final int CMD_USERGRP_RRQ = 21;     // Read user group
    public static final int CMD_USERGRP_WRQ = 22;     // Set user group
    public static final int CMD_USERTZ_RRQ = 23;      // Read user time zone
    public static final int CMD_USERTZ_WRQ = 24;      // Write user time zone
    public static final int CMD_GRPTZ_RRQ = 25;       // Read group time zone
    public static final int CMD_GRPTZ_WRQ = 26;       // Write group time zone
    public static final int CMD_TZ_RRQ = 27;          // Read time zone
    public static final int CMD_TZ_WRQ = 28;          // Write time zone
    public static final int CMD_ULG_RRQ = 29;         // Read unlock combinations
    public static final int CMD_ULG_WRQ = 30;         // Write unlock combinations
    public static final int CMD_UNLOCK = 31;          // Unlock
    public static final int CMD_CLEAR_ACC = 32;       // Reset access control to default
    public static final int CMD_CLEAR_OPLOG = 33;     // Delete all operation logs
    public static final int CMD_OPLOG_RRQ = 34;       // Read operation logs
    public static final int CMD_GET_FREE_SIZES = 50;  // Get machine status (user count, etc.)
    public static final int CMD_ENABLE_CLOCK = 57;    // Set machine to normal working state
    public static final int CMD_STARTVERIFY = 60;     // Set machine to authentication mode
    public static final int CMD_STARTENROLL = 61;     // Start user enrollment
    public static final int CMD_CANCELCAPTURE = 62;   // Cancel capture, return to idle
    public static final int CMD_STATE_RRQ = 64;       // Get machine state
    public static final int CMD_WRITE_LCD = 66;       // Write to LCD
    public static final int CMD_CLEAR_LCD = 67;       // Clear LCD captions
    public static final int CMD_GET_PINWIDTH = 69;    // Get user serial number length
    public static final int CMD_SMS_WRQ = 70;         // Upload short message
    public static final int CMD_SMS_RRQ = 71;         // Download short message
    public static final int CMD_DELETE_SMS = 72;      // Delete short message
    public static final int CMD_UDATA_WRQ = 73;       // Set user's short message
    public static final int CMD_DELETE_UDATA = 74;    // Delete user's short message
    public static final int CMD_DOORSTATE_RRQ = 75;   // Get door state
    public static final int CMD_WRITE_MIFARE = 76;    // Write Mifare card
    public static final int CMD_EMPTY_MIFARE = 78;    // Clear Mifare card

    // Undocumented commands
    public static final int _CMD_GET_USERTEMP = 88;       // Get specific user template (uid, fid)
    public static final int _CMD_SAVE_USERTEMPS = 110;    // Save user and multiple templates
    public static final int _CMD_DEL_USER_TEMP = 134;     // Delete specific user template (uid, fid)

    // Time commands
    public static final int CMD_GET_TIME = 201;       // Get machine time
    public static final int CMD_SET_TIME = 202;       // Set machine time
    public static final int CMD_REG_EVENT = 500;      // Register event

    // Connection commands
    public static final int CMD_CONNECT = 1000;       // Connection request
    public static final int CMD_EXIT = 1001;          // Disconnection request
    public static final int CMD_ENABLEDEVICE = 1002;  // Set machine to normal state
    public static final int CMD_DISABLEDEVICE = 1003; // Set machine to shutdown state
    public static final int CMD_RESTART = 1004;       // Restart machine
    public static final int CMD_POWEROFF = 1005;      // Power off
    public static final int CMD_SLEEP = 1006;         // Set machine to idle
    public static final int CMD_RESUME = 1007;        // Wake up machine (not supported)
    public static final int CMD_CAPTUREFINGER = 1009; // Capture fingerprint image
    public static final int CMD_TEST_TEMP = 1011;     // Test fingerprint existence
    public static final int CMD_CAPTUREIMAGE = 1012;  // Capture full image
    public static final int CMD_REFRESHDATA = 1013;   // Refresh internal data
    public static final int CMD_REFRESHOPTION = 1014; // Refresh configuration
    public static final int CMD_TESTVOICE = 1017;     // Play voice
    public static final int CMD_GET_VERSION = 1100;   // Get firmware version
    public static final int CMD_CHANGE_SPEED = 1101;  // Change transmission speed
    public static final int CMD_AUTH = 1102;          // Connection authorization

    // Data transmission
    public static final int CMD_PREPARE_DATA = 1500;  // Prepare data transmission
    public static final int CMD_DATA = 1501;          // Transmit data packet
    public static final int CMD_FREE_DATA = 1502;     // Clear machine buffer
    public static final int _CMD_PREPARE_BUFFER = 1503; // Init buffer for partial reads
    public static final int _CMD_READ_BUFFER = 1504;    // Read partial data chunk

    // Acknowledgment codes
    public static final int CMD_ACK_OK = 2000;        // Success
    public static final int CMD_ACK_ERROR = 2001;     // Failure
    public static final int CMD_ACK_DATA = 2002;      // Return data
    public static final int CMD_ACK_RETRY = 2003;     // Registered event occurred
    public static final int CMD_ACK_REPEAT = 2004;    // Not available
    public static final int CMD_ACK_UNAUTH = 2005;    // Unauthorized connection

    // Error codes
    public static final int CMD_ACK_UNKNOWN = 0xFFFF; // Unknown command
    public static final int CMD_ACK_ERROR_CMD = 0xFFFD; // Invalid command
    public static final int CMD_ACK_ERROR_INIT = 0xFFFC; // Not initialized
    public static final int CMD_ACK_ERROR_DATA = 0xFFFB; // Data unavailable

    // Event flags
    public static final int EF_ATTLOG = 1;            // Real-time verification success
    public static final int EF_FINGER = (1 << 1);     // Real-time fingerprint press
    public static final int EF_ENROLLUSER = (1 << 2); // Real-time user enrollment
    public static final int EF_ENROLLFINGER = (1 << 3); // Real-time fingerprint enrollment
    public static final int EF_BUTTON = (1 << 4);     // Real-time button press
    public static final int EF_UNLOCK = (1 << 5);     // Real-time unlock
    public static final int EF_VERIFY = (1 << 7);     // Real-time fingerprint verification
    public static final int EF_FPFTR = (1 << 8);      // Real-time fingerprint minutia capture
    public static final int EF_ALARM = (1 << 9);      // Alarm signal

    // User roles
    public static final int USER_DEFAULT = 0;
    public static final int USER_ENROLLER = 2;
    public static final int USER_MANAGER = 6;
    public static final int USER_ADMIN = 14;

    // Function types
    public static final int FCT_ATTLOG = 1;
    public static final int FCT_WORKCODE = 8;
    public static final int FCT_FINGERTMP = 2;
    public static final int FCT_OPLOG = 4;
    public static final int FCT_USER = 5;
    public static final int FCT_SMS = 6;
    public static final int FCT_UDATA = 7;

    // Machine preparation flags
    public static final int MACHINE_PREPARE_DATA_1 = 20560; //0x5050;
    public static final int MACHINE_PREPARE_DATA_2 = 32130; //0x7282;
}