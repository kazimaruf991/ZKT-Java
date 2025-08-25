package com.kmmaruf.zktjava;

import com.kmmaruf.zktjava.exceptions.ZKErrorConnection;
import com.kmmaruf.zktjava.exceptions.ZKErrorResponse;
import com.kmmaruf.zktjava.exceptions.ZKNetworkError;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.LocalDateTime;
import java.util.*;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketException;

public class Base {


    public static <T> T safe_cast(Object val, Class<T> toType, T defaultValue) {
        try {
            if (toType == Integer.class) {
                return toType.cast(Integer.parseInt(val.toString()));
            } else if (toType == Long.class) {
                return toType.cast(Long.parseLong(val.toString()));
            } else if (toType == Double.class) {
                return toType.cast(Double.parseDouble(val.toString()));
            } else if (toType == Float.class) {
                return toType.cast(Float.parseFloat(val.toString()));
            } else if (toType == Boolean.class) {
                return toType.cast(Boolean.parseBoolean(val.toString()));
            } else if (toType == String.class) {
                return toType.cast(val.toString());
            }
        } catch (Exception e) {
            // Ignore and return default
        }
        return defaultValue;
    }

    public byte[] makeCommKey(int key, int sessionId) {
        return makeCommKey(key, sessionId, 50);
    }

    public static byte[] makeCommKey(int key, int sessionId, int ticks) {
        /*
           take a password and session_id and scramble them to send to the machine.
           copied from commpro.c - MakeKey
       */

        int k = 0;

        // Bit reversal logic
        for (int i = 0; i < 32; i++) {
            if ((key & (1 << i)) != 0) {
                k = (k << 1) | 1;
            } else {
                k = k << 1;
            }
        }
        k += sessionId;

        // Pack as unsigned int (4 bytes)
        byte[] packed = BinUtils.packIntLE(k);

        // XOR with 'ZKSO'
        packed[0] ^= 'Z';
        packed[1] ^= 'K';
        packed[2] ^= 'S';
        packed[3] ^= 'O';

        // Unpack as two shorts, swap them
        short h1 = BinUtils.unpackShortLE(packed, 0);
        short h2 = BinUtils.unpackShortLE(packed, 2);
        packed = BinUtils.packShortLE(h2, h1);

        // Final XOR with ticks
        int B = ticks & 0xFF;
        packed[0] ^= B;
        packed[1] ^= B;
        packed[2] = (byte) B;
        packed[3] ^= B;

        return packed;
    }

    public class ZKHelper {
        /**
         * ZK helper class
         */
        private final String ip;
        private final int port;
        private final InetSocketAddress address;

        /**
         * Construct a new 'ZKHelper' object.
         */
        public ZKHelper(String ip, int port) {
            this.ip = ip;
            this.port = port;
            this.address = new InetSocketAddress(ip, port);
        }

        public ZKHelper(String ip) {
            this(ip, 4370);
        }

        /**
         * Returns true if host responds to a ping request
         *
         * @return boolean
         */
        public boolean testPing() {
            // Ping parameters as function of OS
            String os = System.getProperty("os.name").toLowerCase(Locale.ROOT);
            String pingStr = os.contains("windows") ? "-n 1" : "-c 1 -W 5";
            String command = "ping " + pingStr + " " + ip;
            boolean needShell = !os.contains("windows");

            try {
                ProcessBuilder builder = needShell
                        ? new ProcessBuilder("sh", "-c", command)
                        : new ProcessBuilder("cmd.exe", "/c", command);

                Process process = builder.redirectErrorStream(true).start();
                int exitCode = process.waitFor();
                return exitCode == 0;
            } catch (IOException | InterruptedException e) {
                return false;
            }
        }

        /**
         * test TCP connection
         */
        public int testTCP() {
            try (Socket client = new Socket()) {
                client.connect(address, 10_000); // 10 seconds timeout
                return 0; // success
            } catch (IOException e) {
                return 1; // failure
            }
        }

        /**
         * test UDP connection
         */
        public boolean testUDP() {
            try (DatagramSocket client = new DatagramSocket()) {
                client.setSoTimeout(10_000); // 10 seconds timeout
                client.connect(address);
                return true;
            } catch (SocketException e) {
                return false;
            }
        }
    }

    public class ZK {
        /**
         * ZK main class
         */

        private final InetSocketAddress address;
        private DatagramSocket udpSocket;
        private Socket tcpSocket;
        private final int timeout;
        private final int password; // passint
        private int sessionId = 0;
        private int replyId = DeviceConstants.USHRT_MAX - 1;
        private byte[] dataRecv = null;
        private byte[] data = null;

        public boolean isConnect = false;
        public boolean isEnabled = true;
        public ZKHelper helper;
        public boolean forceUdp;
        public boolean ommitPing;
        public boolean verbose;
        public String encoding;
        public boolean tcp;

        public int users = 0;
        public int fingers = 0;
        public int records = 0;
        public int dummy = 0;
        public int cards = 0;
        public int fingersCap = 0;
        public int usersCap = 0;
        public int recCap = 0;
        public int faces = 0;
        public int facesCap = 0;
        public int fingersAv = 0;
        public int usersAv = 0;
        public int recAv = 0;
        public int nextUid = 1;
        public String nextUserId = "1";
        public int userPacketSize = 28; // default zk6
        public boolean endLiveCapture = false;
        private int response;  // Holds the full response payload from device or socket
        private byte[] header;    // Holds the protocol-specific header portion

        /**
         * Construct a new 'ZK' object.
         *
         * @param ip         machine's IP address
         * @param port       machine's port
         * @param timeout    timeout number
         * @param password   passint
         * @param forceUdp   use UDP connection
         * @param ommitPing  check ip using ping before connect
         * @param verbose    showing log while run the commands
         * @param encoding   user encoding
         */
        public ZK(String ip, int port, int timeout, int password,
                  boolean forceUdp, boolean ommitPing, boolean verbose, String encoding) {

            User.ENCODING = encoding;
            this.address = new InetSocketAddress(ip, port);
            this.timeout = timeout;
            this.password = password;

            try {
                this.tcpSocket = new Socket();
                this.tcpSocket.setSoTimeout(timeout * 1000); // milliseconds
            } catch (SocketException e) {
                // Handle socket creation failure
                this.tcpSocket = null;
            }

            try {
                this.udpSocket = new DatagramSocket();
                this.udpSocket.setSoTimeout(timeout * 1000); // milliseconds
            } catch (SocketException e) {
                // Handle socket creation failure
                this.udpSocket = null;
            }

            this.helper = new ZKHelper(ip, port);
            this.forceUdp = forceUdp;
            this.ommitPing = ommitPing;
            this.verbose = verbose;
            this.encoding = encoding;
            this.tcp = !forceUdp;
        }

        // Overloaded constructor with default values
        public ZK(String ip) {
            this(ip, 4370, 60, 0, false, false, false, "UTF-8");
        }


        // Boolean test equivalent of __nonzero__
        public boolean isConnected() {
            return this.isConnect;
        }

        // Socket creation logic
        private void createSocket() {
            try {
                if (this.tcp) {
                    this.tcpSocket = new Socket();
                    this.tcpSocket.connect(this.address, this.timeout * 1000); // timeout in ms
                } else {
                    this.udpSocket = new DatagramSocket();
                    this.udpSocket.setSoTimeout(this.timeout * 1000);
                }
            } catch (IOException e) {
                // Handle connection failure
                this.udpSocket = null;
            }
        }

        // Create TCP top header
        private byte[] createTcpTop(byte[] packet) {
            int length = packet.length;
            ByteBuffer top = ByteBuffer.allocate(8); // 2 shorts + 1 int = 8 bytes
            top.order(ByteOrder.LITTLE_ENDIAN);
            top.putShort((short) DeviceConstants.MACHINE_PREPARE_DATA_1);
            top.putShort((short) DeviceConstants.MACHINE_PREPARE_DATA_2);
            top.putInt(length);
            byte[] topBytes = top.array();

            byte[] result = new byte[topBytes.length + packet.length];
            System.arraycopy(topBytes, 0, result, 0, topBytes.length);
            System.arraycopy(packet, 0, result, topBytes.length, packet.length);
            return result;
        }

        // Create packet header
        private byte[] createHeader(int command, byte[] commandString, int sessionId, int replyId) {
            ByteBuffer buf = ByteBuffer.allocate(8 + commandString.length);
            buf.order(ByteOrder.LITTLE_ENDIAN);
            buf.putShort((short) command);
            buf.putShort((short) 0); // Placeholder
            buf.putShort((short) sessionId);
            buf.putShort((short) replyId);
            buf.put(commandString);

            byte[] rawBuf = buf.array();
            byte[] checksumBuf = createChecksum(rawBuf);
            int checksum = ByteBuffer.wrap(checksumBuf).order(ByteOrder.LITTLE_ENDIAN).getShort() & 0xFFFF;

            replyId += 1;
            if (replyId >= DeviceConstants.USHRT_MAX) {
                replyId -= DeviceConstants.USHRT_MAX;
            }

            ByteBuffer finalBuf = ByteBuffer.allocate(8 + commandString.length);
            finalBuf.order(ByteOrder.LITTLE_ENDIAN);
            finalBuf.putShort((short) command);
            finalBuf.putShort((short) checksum);
            finalBuf.putShort((short) sessionId);
            finalBuf.putShort((short) replyId);
            finalBuf.put(commandString);

            return finalBuf.array();
        }


        // Calculates the checksum of the packet
        private byte[] createChecksum(byte[] p) {
            int l = p.length;
            int checksum = 0;
            int i = 0;

            while (l > 1) {
                int val = ((p[i] & 0xFF) | ((p[i + 1] & 0xFF) << 8));
                checksum += val;
                i += 2;
                l -= 2;
                if (checksum > DeviceConstants.USHRT_MAX) {
                    checksum -= DeviceConstants.USHRT_MAX;
                }
            }

            if (l == 1) {
                checksum += (p[p.length - 1] & 0xFF);
            }

            while (checksum > DeviceConstants.USHRT_MAX) {
                checksum -= DeviceConstants.USHRT_MAX;
            }

            checksum = ~checksum;

            while (checksum < 0) {
                checksum += DeviceConstants.USHRT_MAX;
            }

            ByteBuffer buf = ByteBuffer.allocate(2);
            buf.order(ByteOrder.LITTLE_ENDIAN);
            buf.putShort((short) checksum);
            return buf.array();
        }

        // Tests TCP top header and returns payload size
        private int testTcpTop(byte[] packet) {
            if (packet.length <= 8) return 0;

            ByteBuffer buf = ByteBuffer.wrap(packet, 0, 8).order(ByteOrder.LITTLE_ENDIAN);
            int header1 = buf.getShort() & 0xFFFF;
            int header2 = buf.getShort() & 0xFFFF;
            int length = buf.getInt();

            if (header1 == DeviceConstants.MACHINE_PREPARE_DATA_1 &&
                    header2 == DeviceConstants.MACHINE_PREPARE_DATA_2) {
                return length;
            }
            return 0;
        }

        public Map<String, Object> sendCommand(int command) throws Exception {
            return sendCommand(command, new byte[0], 8);
        }

        public Map<String, Object> sendCommand(int command, byte[] commandString) throws Exception {
            return sendCommand(command, commandString, 8);
        }

        // Sends command to the terminal
        public Map<String, Object> sendCommand(int command, byte[] commandString, int responseSize) throws ZKErrorResponse, ZKErrorConnection, ZKNetworkError {
            if ((command != DeviceConstants.CMD_CONNECT && command != DeviceConstants.CMD_AUTH) && !this.isConnect) {
                throw new ZKErrorConnection("Instance is not connected.");
            }

            byte[] buf = createHeader(command, commandString, this.sessionId, this.replyId);
            try {
                if (this.tcp) {
                    byte[] top = createTcpTop(buf);
                    this.tcpSocket.getOutputStream().write(top);

                    byte[] tcpDataRecv = new byte[responseSize + 8];
                    this.tcpSocket.getInputStream().read(tcpDataRecv);

                    int tcpLength = testTcpTop(tcpDataRecv);
                    if (tcpLength == 0) {
                        throw new ZKNetworkError("TCP packet invalid");
                    }

                    ByteBuffer headerBuf = ByteBuffer.wrap(tcpDataRecv, 8, 8).order(ByteOrder.LITTLE_ENDIAN);
                    this.header = new byte[8];
                    for (int i = 0; i < 4; i++) {
                        short value = (short)(headerBuf.getShort() & 0xFFFF);
                        this.header[i * 2]     = (byte)((value >> 8) & 0xFF); // High byte
                        this.header[i * 2 + 1] = (byte)(value & 0xFF);        // Low byte
                    }

                    this.dataRecv = Arrays.copyOfRange(tcpDataRecv, 8, tcpDataRecv.length);
                } else {

                    this.udpSocket.send(new DatagramPacket(buf, buf.length, this.address));
                    byte[] recvBuf = new byte[responseSize];
                    DatagramPacket packet = new DatagramPacket(recvBuf, recvBuf.length);
                    this.udpSocket.receive(packet);

                    this.dataRecv = recvBuf;
                    ByteBuffer headerBuf = ByteBuffer.wrap(recvBuf, 0, 8).order(ByteOrder.LITTLE_ENDIAN);
                    this.header = new byte[8];
                    for (int i = 0; i < 4; i++) {
                        int value = headerBuf.getShort() & 0xFFFF;
                        this.header[i * 2]     = (byte)((value >> 8) & 0xFF); // High byte
                        this.header[i * 2 + 1] = (byte)(value & 0xFF);        // Low byte
                    }
                }
            } catch (IOException e) {
                throw new ZKNetworkError(e.getMessage());
            }

            this.response = this.header[0];
            this.replyId = this.header[3];
            this.data = Arrays.copyOfRange(this.dataRecv, 8, this.dataRecv.length);

            Map<String, Object> result = new HashMap<>();
            result.put("code", this.response);
            result.put("status", Arrays.asList(
                    DeviceConstants.CMD_ACK_OK,
                    DeviceConstants.CMD_PREPARE_DATA,
                    DeviceConstants.CMD_DATA
            ).contains(this.response));

            return result;
        }

        // Sends ACK_OK event
        private void ackOk() throws Exception{
            byte[] buf = createHeader(DeviceConstants.CMD_ACK_OK, new byte[0], this.sessionId, DeviceConstants.USHRT_MAX - 1);
            try {
                if (this.tcp) {
                    byte[] top = createTcpTop(buf);
                    this.tcpSocket.getOutputStream().write(top);
                } else {
                    this.udpSocket.send(new DatagramPacket(buf, buf.length, this.address));
                }
            } catch (IOException e) {
                throw new ZKNetworkError(e.getMessage());
            }
        }

        // Gets data size from CMD_PREPARE_DATA response
        private int getDataSize() {
            if (this.response == DeviceConstants.CMD_PREPARE_DATA) {
                ByteBuffer buf = ByteBuffer.wrap(this.data, 0, 4).order(ByteOrder.LITTLE_ENDIAN);
                return buf.getInt();
            }
            return 0;
        }

        // Reverses hex string
        private String reverseHex(String hex) {
            StringBuilder data = new StringBuilder();
            for (int i = hex.length() / 2 - 1; i >= 0; i--) {
                data.append(hex, i * 2, i * 2 + 2);
            }
            return data.toString();
        }

        private LocalDateTime decodeTime(byte[] t) {
            ByteBuffer buffer = ByteBuffer.wrap(t).order(ByteOrder.LITTLE_ENDIAN);
            long raw = Integer.toUnsignedLong(buffer.getInt());

            int second = (int)(raw % 60);
            raw /= 60;

            int minute = (int)(raw % 60);
            raw /= 60;

            int hour = (int)(raw % 24);
            raw /= 24;

            int day = (int)(raw % 31) + 1;
            raw /= 31;

            int month = (int)(raw % 12) + 1;
            raw /= 12;

            int year = (int)(raw + 2000);

            return LocalDateTime.of(year, month, day, hour, minute, second);
        }

        private LocalDateTime decodeTimeHex(byte[] timehex) {
            if (timehex.length != 6) throw new IllegalArgumentException("Expected 6 bytes");

            int year   = Byte.toUnsignedInt(timehex[0]) + 2000;
            int month  = Byte.toUnsignedInt(timehex[1]);
            int day    = Byte.toUnsignedInt(timehex[2]);
            int hour   = Byte.toUnsignedInt(timehex[3]);
            int minute = Byte.toUnsignedInt(timehex[4]);
            int second = Byte.toUnsignedInt(timehex[5]);

            return LocalDateTime.of(year, month, day, hour, minute, second);
        }

        private int encodeTime(LocalDateTime t) {
            int year = t.getYear() % 100;
            int month = t.getMonthValue();
            int day = t.getDayOfMonth();
            int hour = t.getHour();
            int minute = t.getMinute();
            int second = t.getSecond();

            return (((year * 12 * 31) + ((month - 1) * 31) + day - 1) * (24 * 60 * 60)) +
                    ((hour * 60 + minute) * 60) + second;
        }

        public ZK connect() throws Exception {
            this.endLiveCapture = false;

            if (!this.ommitPing && !helper.testPing()) {
                throw new ZKNetworkError("Can't reach device (ping " + this.address.getAddress().getHostAddress() + ")");
            }

            if (!this.forceUdp && helper.testTCP() == 0) {
                this.userPacketSize = 72; // default zk8
            }

            createSocket();
            this.sessionId = 0;
            this.replyId = 0xFFFF;

            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_CONNECT);
            this.sessionId = Byte.toUnsignedInt(this.header[2]);

            if ((int) cmdResponse.get("code") == DeviceConstants.CMD_ACK_UNAUTH) {
                if (this.verbose) System.out.println("Try auth");
                byte[] commandString = makeCommKey(this.password, this.sessionId);
                cmdResponse = sendCommand(DeviceConstants.CMD_AUTH, commandString);
            }

            if ((boolean) cmdResponse.get("status")) {
                this.isConnect = true;
                return this;
            } else {
                if ((int) cmdResponse.get("code") == DeviceConstants.CMD_ACK_UNAUTH) {
                    throw new ZKErrorResponse("Unauthenticated");
                }
                if (this.verbose) System.out.println("Connect error response: " + cmdResponse.get("code"));
                throw new ZKErrorResponse("Invalid response: Can't connect");
            }
        }

        public boolean disconnect() throws Exception {
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_EXIT);

            if ((boolean) cmdResponse.get("status")) {
                this.isConnect = false;
                if (this.tcpSocket != null) {
                    this.tcpSocket.close();
                }
                return true;
            } else {
                throw new ZKErrorResponse("Can't disconnect");
            }
        }

        public boolean enableDevice() throws Exception {
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_ENABLEDEVICE);

            if ((boolean) cmdResponse.get("status")) {
                this.isEnabled = true;
                return true;
            } else {
                throw new ZKErrorResponse("Can't enable device");
            }
        }

        public boolean disableDevice() throws Exception {
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_DISABLEDEVICE);

            if ((boolean) cmdResponse.get("status")) {
                this.isEnabled = false;
                return true;
            } else {
                throw new ZKErrorResponse("Can't disable device");
            }
        }

        public String getFirmwareVersion() throws Exception {
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_GET_VERSION, new byte[0], 1024);
            if ((boolean) cmdResponse.get("status")) {
                byte[] firmwareVersion = Arrays.copyOfRange(this.data, 0, indexOf(this.data, (byte) 0));
                return new String(firmwareVersion);
            } else {
                throw new ZKErrorResponse("Can't read firmware version");
            }
        }

        public String getSerialNumber() throws Exception {
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_OPTIONS_RRQ, "~SerialNumber\u0000".getBytes(), 1024);
            if ((boolean) cmdResponse.get("status")) {
                byte[] raw = extractValue(this.data);
                return new String(raw).replace("=", "");
            } else {
                throw new ZKErrorResponse("Can't read serial number");
            }
        }

        public String getPlatform() throws Exception {
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_OPTIONS_RRQ, "~Platform\u0000".getBytes(), 1024);
            if ((boolean) cmdResponse.get("status")) {
                byte[] raw = extractValue(this.data);
                return new String(raw).replace("=", "");
            } else {
                throw new ZKErrorResponse("Can't read platform name");
            }
        }

        public String getMac() throws Exception {
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_OPTIONS_RRQ, "MAC\u0000".getBytes(), 1024);
            if ((boolean) cmdResponse.get("status")) {
                byte[] raw = extractValue(this.data);
                return new String(raw);
            } else {
                throw new ZKErrorResponse("Can't read MAC address");
            }
        }

        public String getDeviceName() throws Exception {
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_OPTIONS_RRQ, "~DeviceName\u0000".getBytes(), 1024);
            if ((boolean) cmdResponse.get("status")) {
                byte[] raw = extractValue(this.data);
                return new String(raw);
            } else {
                return "";
            }
        }

        public int getFaceVersion() throws Exception {
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_OPTIONS_RRQ, "ZKFaceVersion\u0000".getBytes(), 1024);
            if ((boolean) cmdResponse.get("status")) {
                byte[] raw = extractValue(this.data);
                return safeCast(raw, 0);
            } else {
                return 0;
            }
        }

        public int getFpVersion() throws Exception {
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_OPTIONS_RRQ, "~ZKFPVersion\u0000".getBytes(), 1024);
            if ((boolean) cmdResponse.get("status")) {
                byte[] raw = extractValue(this.data);
                return safeCast(raw, 0);
            } else {
                throw new ZKErrorResponse("Can't read fingerprint version");
            }
        }

        public void clearError() throws Exception{
            clearError(new byte[0]);
        }
        public void clearError(byte[] commandString) throws Exception {
            sendCommand(DeviceConstants.CMD_ACK_ERROR, commandString, 1024);
            sendCommand(DeviceConstants.CMD_ACK_UNKNOWN, commandString, 1024);
            sendCommand(DeviceConstants.CMD_ACK_UNKNOWN, commandString, 1024);
            sendCommand(DeviceConstants.CMD_ACK_UNKNOWN, commandString, 1024);
        }

        private byte[] extractValue(byte[] data) {
            int start = indexOf(data, (byte) '=') + 1;
            int end = indexOf(data, (byte) 0, start);
            return Arrays.copyOfRange(data, start, end);
        }

        private int indexOf(byte[] array, byte value) {
            return indexOf(array, value, 0);
        }

        private int indexOf(byte[] array, byte value, int start) {
            for (int i = start; i < array.length; i++) {
                if (array[i] == value) return i;
            }
            return array.length;
        }

        private int safeCast(byte[] raw, int fallback) {
            try {
                return Integer.parseInt(new String(raw).replace("=", ""));
            } catch (NumberFormatException e) {
                return fallback;
            }
        }

        public Integer getExtendFmt() throws Exception {
            byte[] commandString = "~ExtendFmt\u0000".getBytes();
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_OPTIONS_RRQ, commandString, 1024);
            if ((boolean) cmdResponse.get("status")) {
                byte[] fmt = extractValue(this.data);
                return safeCast(fmt, 0);
            } else {
                clearError(commandString);
                return null;
            }
        }

        public Integer getUserExtendFmt() throws Exception {
            byte[] commandString = "~UserExtFmt\u0000".getBytes();
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_OPTIONS_RRQ, commandString, 1024);
            if ((boolean) cmdResponse.get("status")) {
                byte[] fmt = extractValue(this.data);
                return safeCast(fmt, 0);
            } else {
                clearError(commandString);
                return null;
            }
        }

        public Integer getFaceFunOn() throws Exception {
            byte[] commandString = "FaceFunOn\u0000".getBytes();
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_OPTIONS_RRQ, commandString, 1024);
            if ((boolean) cmdResponse.get("status")) {
                byte[] response = extractValue(this.data);
                return safeCast(response, 0);
            } else {
                clearError(commandString);
                return null;
            }
        }

        public Integer getCompatOldFirmware() throws Exception{
            byte[] commandString = "CompatOldFirmware\u0000".getBytes();
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_OPTIONS_RRQ, commandString, 1024);
            if ((boolean) cmdResponse.get("status")) {
                byte[] response = extractValue(this.data);
                return safeCast(response, 0);
            } else {
                clearError(commandString);
                return null;
            }
        }

        public Map<String, String> getNetworkParams() throws Exception{
            String ip = this.address.getHostName();
            String mask = "";
            String gate = "";

            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_OPTIONS_RRQ, "IPAddress\u0000".getBytes(), 1024);
            if ((boolean) cmdResponse.get("status")) {
                ip = new String(extractValue(this.data));
            }

            cmdResponse = sendCommand(DeviceConstants.CMD_OPTIONS_RRQ, "NetMask\u0000".getBytes(), 1024);
            if ((boolean) cmdResponse.get("status")) {
                mask = new String(extractValue(this.data));
            }

            cmdResponse = sendCommand(DeviceConstants.CMD_OPTIONS_RRQ, "GATEIPAddress\u0000".getBytes(), 1024);
            if ((boolean) cmdResponse.get("status")) {
                gate = new String(extractValue(this.data));
            }

            Map<String, String> result = new HashMap<>();
            result.put("ip", ip);
            result.put("mask", mask);
            result.put("gateway", gate);
            return result;
        }

        public int getPinWidth() throws Exception {
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_GET_PINWIDTH, " P".getBytes(), 9);
            if ((boolean) cmdResponse.get("status")) {
                byte[] width = Arrays.copyOfRange(this.data, 0, indexOf(this.data, (byte) 0));
                return Byte.toUnsignedInt(width[0]);
            } else {
                throw new ZKErrorResponse("can't get pin width");
            }
        }

        public boolean freeData() throws Exception {
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_FREE_DATA, new byte[0], 0);
            if ((boolean) cmdResponse.get("status")) {
                return true;
            } else {
                throw new ZKErrorResponse("can't free data");
            }
        }

        public boolean readSizes() throws Exception {
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_GET_FREE_SIZES, new byte[0], 1024);
            if ((boolean) cmdResponse.get("status")) {
                if (this.verbose) {
                    System.out.println(BinUtils.byteArrayToHex(this.data));
                }

                if (this.data.length >= 80) {
                    ByteBuffer buf = ByteBuffer.wrap(this.data).order(ByteOrder.LITTLE_ENDIAN);
                    int[] fields = new int[20];
                    for (int i = 0; i < 20; i++) {
                        fields[i] = buf.getInt();
                    }
                    this.users = fields[4];
                    this.fingers = fields[6];
                    this.records = fields[8];
                    this.dummy = fields[10];
                    this.cards = fields[12];
                    this.fingersCap = fields[14];
                    this.usersCap = fields[15];
                    this.recCap = fields[16];
                    this.fingersAv = fields[17];
                    this.usersAv = fields[18];
                    this.recAv = fields[19];
                    this.data = Arrays.copyOfRange(this.data, 80, this.data.length);
                }

                if (this.data.length >= 12) {
                    ByteBuffer buf = ByteBuffer.wrap(this.data).order(ByteOrder.LITTLE_ENDIAN);
                    int[] faceFields = new int[3];
                    for (int i = 0; i < 3; i++) {
                        faceFields[i] = buf.getInt();
                    }
                    this.faces = faceFields[0];
                    this.facesCap = faceFields[2];
                }

                return true;
            } else {
                throw new ZKErrorResponse("can't read sizes");
            }
        }

        public boolean unlock(int timeInSeconds) throws Exception {
            int delay = timeInSeconds * 10;
            byte[] commandString = BinUtils.packIntLE(delay);
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_UNLOCK, commandString);
            if ((boolean) cmdResponse.get("status")) {
                return true;
            } else {
                throw new ZKErrorResponse("Can't open door");
            }
        }

        public boolean getLockState() throws Exception{
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_DOORSTATE_RRQ);
            return (boolean) cmdResponse.get("status");
        }

        @Override
        public String toString() {
            return String.format("ZK %s://%s:%d users[%d]:%d/%d fingers:%d/%d, records:%d/%d faces:%d/%d",
                    this.tcp ? "tcp" : "udp",
                    this.address.getHostName(),
                    this.address.getPort(),
                    this.userPacketSize,
                    this.users, this.usersCap,
                    this.fingers, this.fingersCap,
                    this.records, this.recCap,
                    this.faces, this.facesCap
            );
        }

        public boolean restart() throws Exception {
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_RESTART);
            if ((boolean) cmdResponse.get("status")) {
                this.isConnect = false;
                this.nextUid = 1;
                return true;
            } else {
                throw new ZKErrorResponse("Can't restart device");
            }
        }

        public boolean writeLcd(int lineNumber, String text) throws Exception {
            ByteBuffer buf = ByteBuffer.allocate(3 + text.length());
            buf.order(ByteOrder.LITTLE_ENDIAN);
            buf.putShort((short) lineNumber);
            buf.put((byte) 0);
            buf.put((byte) ' ');
            buf.put(text.getBytes(this.encoding));
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_WRITE_LCD, buf.array());
            if ((boolean) cmdResponse.get("status")) {
                return true;
            } else {
                throw new ZKErrorResponse("Can't write LCD");
            }
        }

        public boolean clearLcd() throws Exception {
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_CLEAR_LCD);
            if ((boolean) cmdResponse.get("status")) {
                return true;
            } else {
                throw new ZKErrorResponse("Can't clear LCD");
            }
        }

        public LocalDateTime getTime() throws Exception {
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_GET_TIME, new byte[0], 1032);
            if ((boolean) cmdResponse.get("status")) {
                byte[] timeBytes = Arrays.copyOfRange(this.data, 0, 4);
                return decodeTime(timeBytes);
            } else {
                throw new ZKErrorResponse("Can't get time");
            }
        }

        public boolean setTime(LocalDateTime timestamp) throws Exception {
            int encoded = encodeTime(timestamp);
            byte[] commandString = BinUtils.packIntLE(encoded);
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_SET_TIME, commandString);
            if ((boolean) cmdResponse.get("status")) {
                return true;
            } else {
                throw new ZKErrorResponse("Can't set time");
            }
        }

        public boolean powerOff() throws Exception {
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_POWEROFF, new byte[0], 1032);
            if ((boolean) cmdResponse.get("status")) {
                this.isConnect = false;
                this.nextUid = 1;
                return true;
            } else {
                throw new ZKErrorResponse("Can't power off");
            }
        }

        public boolean refreshData() throws Exception {
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_REFRESHDATA);
            if ((boolean) cmdResponse.get("status")) {
                return true;
            } else {
                throw new ZKErrorResponse("Can't refresh data");
            }
        }

        public void setUser(Integer uid, String name, int privilege, String password, String groupId, String userId, int card) throws Exception {
            int userPacketSize = this.userPacketSize;
            if (uid == null) {
                uid = this.nextUid;
                if (userId == null || userId.isEmpty()) {
                    userId = this.nextUserId;
                }
            }
            if (userId == null || userId.isEmpty()) {
                userId = String.valueOf(uid);
            }
            if (privilege != DeviceConstants.USER_DEFAULT && privilege != DeviceConstants.USER_ADMIN) {
                privilege = DeviceConstants.USER_DEFAULT;
            }

            byte[] commandString;
            if (userPacketSize == 28) {
                int group = (groupId == null || groupId.isEmpty()) ? 0 : Integer.parseInt(groupId);
                try {
                    commandString = pack("HB5s8sIxBHI", uid, privilege,
                            password.getBytes(this.encoding),
                            name.getBytes(this.encoding),
                            card, group, 0, Integer.parseInt(userId));
                } catch (Exception e) {
                    if (this.verbose) {
                        System.out.println("Error packing user: " + e.getMessage());
                    }
                    throw new ZKErrorResponse("Can't pack user");
                }
            } else {
                byte[] namePad = Arrays.copyOf(name.getBytes(this.encoding), 24);
                byte[] cardStr = pack("<I", card);
                commandString = pack("HB8s24s4sx7sx24s", uid, privilege,
                        password.getBytes(this.encoding),
                        namePad, cardStr,
                        groupId.getBytes(this.encoding),
                        userId.getBytes(this.encoding));
            }

            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_USER_WRQ, commandString, 1024);
            if (this.verbose) {
                System.out.println("Response: " + cmdResponse);
            }
            if (!(boolean) cmdResponse.get("status")) {
                throw new ZKErrorResponse("Can't set user");
            }

            refreshData();
            if (this.nextUid == uid) {
                this.nextUid++;
            }
            if (this.nextUserId.equals(userId)) {
                this.nextUserId = String.valueOf(this.nextUid);
            }
        }

        public void saveUserTemplate(Object userRef, List<Finger> fingers) throws Exception {
            User user = resolveUser(userRef);
            if (fingers == null) fingers = new ArrayList<>();
            HRSaveUserTemplates(Collections.singletonList(new AbstractMap.SimpleEntry<>(user, fingers)));
        }

        private User resolveUser(Object ref) throws Exception {
            if (ref instanceof User) return (User) ref;
            List<User> users = getUsers();
            for (User u : users) {
                if (u.userId.equals(String.valueOf(ref))) {
                    return u;
                }
            }
            throw new ZKErrorResponse("Can't find user");
        }

        public void HRSaveUserTemplates(List<Map.Entry<User, List<Finger>>> userTemplates) throws Exception {
            ByteArrayOutputStream upack = new ByteArrayOutputStream();
            ByteArrayOutputStream fpack = new ByteArrayOutputStream();
            ByteArrayOutputStream table = new ByteArrayOutputStream();
            int fnum = 0x10;
            int tstart = 0;

            for (Map.Entry<User, List<Finger>> entry : userTemplates) {
                User user = entry.getKey();
                List<Finger> fingers = entry.getValue();
                if (this.userPacketSize == 28) {
                    upack.writeBytes(user.repack29());
                } else {
                    upack.writeBytes(user.repack73());
                }
                for (Finger finger : fingers) {
                    byte[] tfp = finger.repack_only();
                    table.writeBytes(pack("<bHbI", 2, user.uid, fnum + finger.fid, tstart));
                    tstart += tfp.length;
                    fpack.writeBytes(tfp);
                }
            }

            byte[] head = pack("III", upack.size(), table.size(), fpack.size());
            byte[] packet = concat(head, upack.toByteArray(), table.toByteArray(), fpack.toByteArray());
            sendWithBuffer(packet);

            byte[] commandString = pack("<IHH", 12, 0, 8);
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants._CMD_SAVE_USERTEMPS, commandString);
            if (!(boolean) cmdResponse.get("status")) {
                throw new ZKErrorResponse("Can't save usertemplates");
            }
            refreshData();
        }

        private void sendWithBuffer(byte[] buffer) throws Exception {
            final int MAX_CHUNK = 1024;
            int size = buffer.length;
            freeData();

            byte[] commandString = pack("I", size);
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_PREPARE_DATA, commandString);
            if (!(boolean) cmdResponse.get("status")) {
                throw new ZKErrorResponse("Can't prepare data");
            }

            int packets = size / MAX_CHUNK;
            int remain = size % MAX_CHUNK;
            int start = 0;

            for (int i = 0; i < packets; i++) {
                sendChunk(Arrays.copyOfRange(buffer, start, start + MAX_CHUNK));
                start += MAX_CHUNK;
            }
            if (remain > 0) {
                sendChunk(Arrays.copyOfRange(buffer, start, start + remain));
            }
        }

        private boolean sendChunk(byte[] commandString) throws Exception {
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_DATA, commandString);
            if ((boolean) cmdResponse.get("status")) {
                return true;
            } else {
                throw new ZKErrorResponse("Can't send chunk");
            }
        }

        // Pack values into byte array using format string
        public static byte[] pack(String format, Object... values) {
            ByteBuffer buffer = ByteBuffer.allocate(1024).order(ByteOrder.LITTLE_ENDIAN);
            int index = 0;

            for (char fmt : format.toCharArray()) {
                switch (fmt) {
                    case 'B': buffer.put((byte) ((int) values[index++])); break;
                    case 'H': buffer.putShort((short) ((int) values[index++])); break;
                    case 'I': buffer.putInt((int) values[index++]); break;
                    case 's':
                        byte[] strBytes = (byte[]) values[index++];
                        buffer.put(strBytes);
                        break;
                    case 'x': buffer.put((byte) 0); break; // padding
                    default: throw new IllegalArgumentException("Unsupported format: " + fmt);
                }
            }

            buffer.flip();
            byte[] packed = new byte[buffer.limit()];
            buffer.get(packed);
            return packed;
        }

        // Unpack byte array into values using format string
        public static Object[] unpack(String format, byte[] data) {
            ByteBuffer buffer = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
            List<Object> result = new ArrayList<>();

            for (char fmt : format.toCharArray()) {
                switch (fmt) {
                    case 'B': result.add(buffer.get() & 0xFF); break;
                    case 'H': result.add(buffer.getShort() & 0xFFFF); break;
                    case 'I': result.add(buffer.getInt()); break;
                    case 'x': buffer.get(); break; // skip padding
                    default: throw new IllegalArgumentException("Unsupported format: " + fmt);
                }
            }

            return result.toArray();
        }

        public static Object[] unpack(String format, byte[] data, int offset) {
            List<Object> result = new ArrayList<>();
            ByteBuffer buffer = ByteBuffer.wrap(data);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.position(offset);

            int i = 0;
            while (i < format.length()) {
                char c = format.charAt(i);
                switch (c) {
                    case 'H': // unsigned short (2 bytes)
                        result.add(buffer.getShort() & 0xFFFF);
                        break;
                    case 'I': // unsigned int (4 bytes)
                        result.add(buffer.getInt() & 0xFFFFFFFFL);
                        break;
                    case 'B': // unsigned byte (1 byte)
                        result.add(buffer.get() & 0xFF);
                        break;
                    case 's': // byte string
                        // Look ahead for length prefix (e.g., '8s')
                        int lenStart = i - 1;
                        while (lenStart >= 0 && Character.isDigit(format.charAt(lenStart))) lenStart--;
                        String lenStr = format.substring(lenStart + 1, i);
                        int len = Integer.parseInt(lenStr);
                        byte[] strBytes = new byte[len];
                        buffer.get(strBytes);
                        result.add(strBytes);
                        i += lenStr.length(); // skip length digits
                        break;
                    default:
                        throw new IllegalArgumentException("Unsupported format: " + c);
                }
                i++;
            }

            return result.toArray();
        }

        // Concatenate multiple byte arrays
        public static byte[] concat(byte[]... arrays) {
            int totalLength = Arrays.stream(arrays).mapToInt(a -> a.length).sum();
            byte[] result = new byte[totalLength];
            int offset = 0;

            for (byte[] array : arrays) {
                System.arraycopy(array, 0, result, offset, array.length);
                offset += array.length;
            }

            return result;
        }

        // Convenience method for packing a single int (little-endian)
        public static byte[] packIntLE(int value) {
            ByteBuffer buffer = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN);
            buffer.putInt(value);
            return buffer.array();
        }

        public boolean deleteUserTemplate(int uid, int tempId, String userId) throws Exception {
            if (this.tcp && userId != null && !userId.isEmpty()) {
                byte[] commandString = pack("<24sB", userId.getBytes(this.encoding), tempId);
                Map<String, Object> cmdResponse = sendCommand(DeviceConstants._CMD_DEL_USER_TEMP, commandString);
                return (boolean) cmdResponse.get("status");
            }

            if (uid == 0) {
                List<User> users = getUsers();
                for (User u : users) {
                    if (u.userId.equals(userId)) {
                        uid = u.uid;
                        break;
                    }
                }
                if (uid == 0) return false;
            }

            byte[] commandString = pack("hb", uid, tempId);
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_DELETE_USERTEMP, commandString);
            return (boolean) cmdResponse.get("status");
        }

        public boolean deleteUser(int uid, String userId) throws Exception {
            if (uid == 0) {
                List<User> users = getUsers();
                for (User u : users) {
                    if (u.userId.equals(userId)) {
                        uid = u.uid;
                        break;
                    }
                }
                if (uid == 0) return false;
            }

            byte[] commandString = pack("h", uid);
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_DELETE_USER, commandString);
            if (!(boolean) cmdResponse.get("status")) {
                throw new ZKErrorResponse("Can't delete user");
            }

            refreshData();
            if (uid == (this.nextUid - 1)) {
                this.nextUid = uid;
            }
            return true;
        }

        public Finger getUserTemplate(String uidStr, int tempId, String userId) throws Exception {
            int uid = 0;
            if (uidStr == null || uidStr.isEmpty()) {
                List<User> users = getUsers();
                for (User u : users) {
                    if (u.userId.equals(userId)) {
                        uid = u.uid;
                        break;
                    }
                }
                if (uid == 0) return null;
            } else {
                uid = Integer.parseInt(uidStr);
            }

            for (int retries = 0; retries < 3; retries++) {
                byte[] commandString = pack("hb", uid, tempId);
                Map<String, Object> cmdResponse = sendCommand(DeviceConstants._CMD_GET_USERTEMP, commandString, 1032);
                byte[] data = receiveChunk();
                if (data != null) {
                    byte[] resp = Arrays.copyOf(data, data.length - 1);
                    if (resp.length >= 6 && Arrays.equals(Arrays.copyOfRange(resp, resp.length - 6, resp.length), new byte[6])) {
                        resp = Arrays.copyOf(resp, resp.length - 6);
                    }
                    return new Finger(uid, tempId, 1, resp);
                }
                if (this.verbose) System.out.println("retry get_user_template");
            }

            if (this.verbose) System.out.println("Can't read/find finger");
            return null;
        }

        public List<Finger> getTemplates() throws Exception {
            readSizes();
            if (this.fingers == 0) return new ArrayList<>();

            List<Finger> templates = new ArrayList<>();
            Pair<byte[], Integer> result = readWithBuffer(DeviceConstants.CMD_DB_RRQ, DeviceConstants.FCT_FINGERTMP);
            byte[] templatedata = result.getKey();
            int size = result.getValue();

            if (size < 4) {
                if (this.verbose) System.out.println("WRN: no user data");
                return templates;
            }

            int totalSize = (int) unpack("i", Arrays.copyOfRange(templatedata, 0, 4))[0];
            if (this.verbose) {
                System.out.printf("get template total size %d, size %d len %d%n", totalSize, size, templatedata.length);
            }

            templatedata = Arrays.copyOfRange(templatedata, 4, templatedata.length);
            while (totalSize > 0 && templatedata.length >= 6) {
                Object[] header = unpack("HHbb", Arrays.copyOfRange(templatedata, 0, 6));
                int recordSize = (int) header[0];
                int uid = (int) header[1];
                int fid = (byte) header[2];
                int valid = (byte) header[3];

                byte[] template = Arrays.copyOfRange(templatedata, 6, recordSize);
                Finger finger = new Finger(uid, fid, valid, template);
                if (this.verbose) System.out.println(finger);

                templates.add(finger);
                templatedata = Arrays.copyOfRange(templatedata, recordSize, templatedata.length);
                totalSize -= recordSize;
            }

            return templates;
        }

        public List<User> getUsers() throws Exception {
            readSizes();
            if (this.users == 0) {
                this.nextUid = 1;
                this.nextUserId = "1";
                return new ArrayList<>();
            }

            List<User> users = new ArrayList<>();
            int maxUid = 0;
            Pair<byte[], Integer> result = readWithBuffer(DeviceConstants.CMD_USERTEMP_RRQ, DeviceConstants.FCT_USER);
            byte[] userdata = result.getKey();
            int size = result.getValue();

            if (this.verbose) {
                System.out.printf("user size %d (= %d)%n", size, userdata.length);
            }

            if (size <= 4) {
                System.out.println("WRN: missing user data");
                return new ArrayList<>();
            }

            int totalSize = (int) unpack("I", Arrays.copyOfRange(userdata, 0, 4))[0];
            this.userPacketSize = totalSize / this.users;

            if (this.userPacketSize != 28 && this.userPacketSize != 72) {
                if (this.verbose) {
                    System.out.printf("WRN packet size would be %d%n", this.userPacketSize);
                }
            }

            userdata = Arrays.copyOfRange(userdata, 4, userdata.length);

            if (this.userPacketSize == 28) {
                while (userdata.length >= 28) {
                    byte[] chunk = Arrays.copyOf(userdata, 28);
                    Object[] fields = unpack("<HB5s8sIxBhI", chunk);
                    int uid = (int) fields[0];
                    int privilege = (int) fields[1];
                    String password = new String((byte[]) fields[2], this.encoding).split("\0")[0];
                    String name = new String((byte[]) fields[3], this.encoding).split("\0")[0].trim();
                    int card = (int) fields[4];
                    String groupId = String.valueOf(fields[5]);
                    String userId = String.valueOf(fields[7]);

                    if (uid > maxUid) maxUid = uid;
                    if (name.isEmpty()) name = "NN-" + userId;

                    users.add(new User(uid, name, privilege, password, groupId, userId, card));

                    if (this.verbose) {
                        System.out.printf("[6]user: %d %d %s %s %d %s %d %s%n",
                                uid, privilege, password, name, card, groupId, (int) fields[6], userId);
                    }

                    userdata = Arrays.copyOfRange(userdata, 28, userdata.length);
                }
            } else {
                while (userdata.length >= 72) {
                    byte[] chunk = Arrays.copyOf(userdata, 72);
                    Object[] fields = unpack("<HB8s24sIx7sx24s", chunk);
                    int uid = (int) fields[0];
                    int privilege = (int) fields[1];
                    String password = new String((byte[]) fields[2], this.encoding).split("\0")[0];
                    String name = new String((byte[]) fields[3], this.encoding).split("\0")[0].trim();
                    String groupId = new String((byte[]) fields[5], this.encoding).split("\0")[0].trim();
                    String userId = new String((byte[]) fields[6], this.encoding).split("\0")[0];
                    int card = (int) fields[4];

                    if (uid > maxUid) maxUid = uid;
                    if (name.isEmpty()) name = "NN-" + userId;

                    users.add(new User(uid, name, privilege, password, groupId, userId, card));
                    userdata = Arrays.copyOfRange(userdata, 72, userdata.length);
                }
            }

            maxUid++;
            this.nextUid = maxUid;
            this.nextUserId = String.valueOf(maxUid);

            while (true) {
                boolean exists = users.stream().anyMatch(u -> u.userId.equals(this.nextUserId));
                if (exists) {
                    maxUid++;
                    this.nextUserId = String.valueOf(maxUid);
                } else {
                    break;
                }
            }

            return users;
        }

        public boolean cancelCapture() throws Exception {
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_CANCELCAPTURE);
            return (boolean) cmdResponse.get("status");
        }

        public boolean verifyUser() throws Exception {
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_STARTVERIFY);
            if ((boolean) cmdResponse.get("status")) {
                return true;
            } else {
                throw new ZKErrorResponse("Can't Verify");
            }
        }

        public void registerEvent(int flags) throws Exception {
            byte[] commandString = pack("I", flags);
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_REG_EVENT, commandString);
            if (!(boolean) cmdResponse.get("status")) {
                throw new ZKErrorResponse("Can't register events " + flags);
            }
        }

        public boolean setSdkBuild1() throws Exception{
            byte[] commandString = "SDKBuild=1".getBytes();
            Map<String, Object> cmdResponse = sendCommand(DeviceConstants.CMD_OPTIONS_WRQ, commandString);
            return (boolean) cmdResponse.get("status");
        }


        public boolean enrollUser(int uid, int tempId, String userId) throws Exception {
            int command = DeviceConstants.CMD_STARTENROLL;
            boolean done = false;

            if (userId == null || userId.isEmpty()) {
                List<User> users = getUsers();
                Optional<User> match = users.stream().filter(u -> u.uid == uid).findFirst();
                if (match.isPresent()) {
                    userId = match.get().userId;
                } else {
                    return false;
                }
            }

            byte[] commandString;
            if (this.tcp) {
                commandString = pack("<24sbb", userId.getBytes(), tempId, 1);
            } else {
                commandString = pack("<Ib", Integer.parseInt(userId), tempId);
            }

            cancelCapture();
            Map<String, Object> cmdResponse = sendCommand(command, commandString);
            if (!(Boolean) cmdResponse.get("status")) {
                throw new ZKErrorResponse(String.format("Can't Enroll user #%d [%d]", uid, tempId));
            }

            this.tcpSocket.setSoTimeout(60000);
            this.udpSocket.setSoTimeout(60000);
            int attempts = 3;

            while (attempts > 0) {
                if (this.verbose) System.out.printf("A:%d esperando primer regevent%n", attempts);
                byte[] dataRecv = recvBytes(1032);
                ackOk();
                if (this.verbose) System.out.println(BinUtils.byteArrayToHex(dataRecv));

                int res = extractResult(dataRecv);
                if (this.verbose) System.out.printf("res %d%n", res);

                if (res == 0 || res == 6 || res == 4) {
                    if (this.verbose) System.out.println("posible timeout o reg Fallido");
                    break;
                }

                if (this.verbose) System.out.printf("A:%d esperando 2do regevent%n", attempts);
                dataRecv = recvBytes(1032);
                ackOk();
                if (this.verbose) System.out.println(BinUtils.byteArrayToHex(dataRecv));

                res = extractResult(dataRecv);
                if (this.verbose) System.out.printf("res %d%n", res);

                if (res == 6 || res == 4) {
                    if (this.verbose) System.out.println("posible timeout o reg Fallido");
                    break;
                } else if (res == 0x64) {
                    if (this.verbose) System.out.println("ok, continue?");
                    attempts--;
                }
            }

            if (attempts == 0) {
                byte[] dataRecv = recvBytes(1032);
                ackOk();
                if (this.verbose) System.out.println(BinUtils.byteArrayToHex(dataRecv));

                int res = extractResult(dataRecv);
                if (this.verbose) System.out.printf("res %d%n", res);

                if (res == 5 && this.verbose) System.out.println("finger duplicate");
                if ((res == 6 || res == 4) && this.verbose) System.out.println("posible timeout");

                if (res == 0) {
                    int size = (int) unpack("H", pad(dataRecv, tcp ? 24 : 16), tcp ? 10 : 10)[0];
                    int pos = (int) unpack("H", pad(dataRecv, tcp ? 24 : 16), tcp ? 12 : 12)[0];
                    if (this.verbose) System.out.printf("enroll ok %d %d%n", size, pos);
                    done = true;
                }
            }

            this.tcpSocket.setSoTimeout(this.timeout);
            this.udpSocket.setSoTimeout(this.timeout);
            registerEvent(0); // TODO: test
            cancelCapture();
            verifyUser();
            return done;
        }

        // Helper methods
        private byte[] recvBytes(int length) throws IOException {
            byte[] buffer = new byte[length];
            InputStream in = this.tcpSocket.getInputStream();
            int read = in.read(buffer);
            return Arrays.copyOf(buffer, read);
        }

        private int extractResult(byte[] dataRecv) {
            byte[] padded = pad(dataRecv, tcp ? 24 : 16);
            int offset = tcp ? 16 : 8;
            return (int) unpack("H", padded, offset)[0];
        }

        private byte[] pad(byte[] data, int length) {
            return Arrays.copyOf(data, Math.max(data.length, length));
        }

        public void liveCapture(int newTimeout, EventListener listener) throws Exception {
            boolean wasEnabled = this.isEnabled;
            List<User> users = getUsers();

            cancelCapture();
            verifyUser();

            if (!this.isEnabled) {
                enableDevice();
            }

            if (this.verbose) System.out.println("start live_capture");

            registerEvent(DeviceConstants.EF_ATTLOG);
            this.tcpSocket.setSoTimeout(newTimeout * 1000);
            this.udpSocket.setSoTimeout(newTimeout * 1000);
            this.endLiveCapture = false;

            while (!this.endLiveCapture) {
                try {
                    if (this.verbose) System.out.println("esperando event");

                    byte[] dataRecv = recvBytes(1032);
                    ackOk();

                    int size;
                    Object[] header;
                    byte[] data;

                    if (this.tcp) {
                        size = (int) unpack("<HHI", dataRecv, 0)[2];
                        header = unpack("HHHH", dataRecv, 8);
                        data = Arrays.copyOfRange(dataRecv, 16, dataRecv.length);
                    } else {
                        size = dataRecv.length;
                        header = unpack("<4H", dataRecv, 0);
                        data = Arrays.copyOfRange(dataRecv, 8, dataRecv.length);
                    }

                    if ((int) header[0] != DeviceConstants.CMD_REG_EVENT) {
                        if (this.verbose) System.out.printf("not event! %x%n", header[0]);
                        continue;
                    }

                    if (data.length == 0) {
                        if (this.verbose) System.out.println("empty");
                        continue;
                    }

                    while (data.length >= 10) {
                        Object[] fields = null;
                        int packetSize = data.length;

                        if (packetSize == 10) {
                            fields = unpack("<HBB6s", data, 0);
                            data = Arrays.copyOfRange(data, 10, data.length);
                        } else if (packetSize == 12) {
                            fields = unpack("<IBB6s", data, 0);
                            data = Arrays.copyOfRange(data, 12, data.length);
                        } else if (packetSize == 14) {
                            fields = unpack("<HBB6s4s", data, 0);
                            data = Arrays.copyOfRange(data, 14, data.length);
                        } else if (packetSize == 32) {
                            fields = unpack("<24sBB6s", data, 0);
                            data = Arrays.copyOfRange(data, 32, data.length);
                        } else if (packetSize == 36) {
                            fields = unpack("<24sBB6s4s", data, 0);
                            data = Arrays.copyOfRange(data, 36, data.length);
                        } else if (packetSize == 37) {
                            fields = unpack("<24sBB6s5s", data, 0);
                            data = Arrays.copyOfRange(data, 37, data.length);
                        } else if (packetSize >= 52) {
                            fields = unpack("<24sBB6s20s", data, 0);
                            data = Arrays.copyOfRange(data, 52, data.length);
                        }

                        if (fields == null) continue;

                        Object rawUserId = fields[0];
                        int status = (int) fields[1];
                        int punch = (int) fields[2];
                        byte[] timehex = (byte[]) fields[3];

                        String userId;
                        if (rawUserId instanceof Integer) {
                            userId = String.valueOf(rawUserId);
                        } else {
                            userId = new String((byte[]) rawUserId).split("\0")[0];
                        }

                        LocalDateTime timestamp = decodeTimeHex(timehex);
                        Optional<User> matched = users.stream().filter(u -> u.userId.equals(userId)).findFirst();
                        int uid = matched.map(u -> u.uid).orElse(Integer.parseInt(userId));

                        listener.onEvent(new Attendance(userId, timestamp, status, punch, uid));
                    }

                } catch (SocketTimeoutException e) {
                    if (this.verbose) System.out.println("time out");
                    listener.onEvent(null); // keep watching
                } catch (InterruptedIOException | RuntimeException e) {
                    if (this.verbose) System.out.println("break");
                    break;
                }
            }

            if (this.verbose) System.out.println("exit gracefully");

            this.tcpSocket.setSoTimeout(this.timeout * 1000);
            this.udpSocket.setSoTimeout(this.timeout * 1000);
            registerEvent(0);

            if (!wasEnabled) {
                disableDevice();
            }
        }

        public interface EventListener {
            void onEvent(Attendance attendance);
        }

        public boolean clearData() throws Exception {
            int command = DeviceConstants.CMD_CLEAR_DATA;
            byte[] commandString = new byte[0];
            Map<String, Object> cmdResponse = sendCommand(command, commandString);

            if ((boolean) cmdResponse.get("status")) {
                this.nextUid = 1;
                return true;
            } else {
                throw new ZKErrorResponse("Can't clear data");
            }
        }

        public class TcpResult {
            public final byte[] payload;
            public final byte[] remainder;

            public TcpResult(byte[] payload, byte[] remainder) {
                this.payload = payload;
                this.remainder = remainder;
            }
        }

        private TcpResult receiveTcpData(byte[] dataRecv, int size) throws IOException {
            List<byte[]> dataChunks = new ArrayList<>();
            int tcpLength = testTcpTop(dataRecv);

            if (verbose) System.out.printf("tcp_length %d, size %d%n", tcpLength, size);
            if (tcpLength <= 0) {
                if (verbose) System.out.println("Incorrect tcp packet");
                return new TcpResult(null, new byte[0]);
            }

            if ((tcpLength - 8) < size) {
                if (verbose) System.out.println("tcp length too small... retrying");

                TcpResult partial = receiveTcpData(dataRecv, tcpLength - 8);
                dataChunks.add(partial.payload);
                size -= partial.payload.length;

                if (verbose) System.out.printf("new tcp DATA packet to fill missing %d%n", size);
                byte[] newRecv = concat(partial.remainder, recvBytes(size + 16));

                if (verbose) System.out.printf("new tcp DATA starting with %d bytes%n", newRecv.length);
                TcpResult finalPart = receiveTcpData(newRecv, size);
                dataChunks.add(finalPart.payload);

                if (verbose) System.out.printf("for missing %d received %d with extra %d%n",
                        size, finalPart.payload.length, finalPart.remainder.length);

                return new TcpResult(concatAll(dataChunks), finalPart.remainder);
            }

            int received = dataRecv.length;
            if (verbose) System.out.printf("received %d, size %d%n", received, size);

            int response = (int) unpack("HHHH", dataRecv, 8)[0];
            if (received >= (size + 32)) {
                if (response == DeviceConstants.CMD_DATA) {
                    byte[] payload = Arrays.copyOfRange(dataRecv, 16, size + 16);
                    if (verbose) System.out.printf("resp complete len %d%n", payload.length);
                    byte[] remainder = Arrays.copyOfRange(dataRecv, size + 16, dataRecv.length);
                    return new TcpResult(payload, remainder);
                } else {
                    if (verbose) System.out.printf("incorrect response!!! %d%n", response);
                    return new TcpResult(null, new byte[0]);
                }
            } else {
                if (verbose) System.out.printf("try DATA incomplete (actual valid %d)%n", received - 16);
                dataChunks.add(Arrays.copyOfRange(dataRecv, 16, size + 16));
                size -= (received - 16);

                byte[] brokenHeader = new byte[0];
                if (size < 0) {
                    brokenHeader = Arrays.copyOfRange(dataRecv, size, dataRecv.length);
                    if (verbose) System.out.println("broken " + BinUtils.byteArrayToHex(brokenHeader));
                }

                if (size > 0) {
                    byte[] extra = receiveRawData(size);
                    dataChunks.add(extra);
                }

                return new TcpResult(concatAll(dataChunks), brokenHeader);
            }
        }

        private byte[] receiveRawData(int size) throws IOException {
            List<byte[]> chunks = new ArrayList<>();
            if (verbose) System.out.printf("expecting %d bytes raw data%n", size);

            while (size > 0) {
                byte[] recv = recvBytes(size);
                int received = recv.length;

                if (verbose) System.out.printf("partial recv %d%n", received);
                if (received < 100 && verbose) System.out.println("   recv " + BinUtils.byteArrayToHex(recv));

                chunks.add(recv);
                size -= received;

                if (verbose) System.out.printf("still need %d%n", size);
            }

            return concatAll(chunks);
        }

        private byte[] receiveChunk() throws Exception {
            if (this.response == DeviceConstants.CMD_DATA) {
                if (tcp) {
                    if (verbose) System.out.printf("_rc_DATA! is %d bytes, tcp length is %d%n", data.length, tcpLength);
                    if (data.length < (tcpLength - 8)) {
                        int need = (tcpLength - 8) - data.length;
                        if (verbose) System.out.printf("need more data: %d%n", need);
                        byte[] more = receiveRawData(need);
                        return concat(data, more);
                    } else {
                        if (verbose) System.out.println("Enough data");
                        return data;
                    }
                } else {
                    if (verbose) System.out.printf("_rc len is %d%n", data.length);
                    return data;
                }
            } else if (this.response == DeviceConstants.CMD_PREPARE_DATA) {
                List<byte[]> chunks = new ArrayList<>();
                int size = getDataSize();

                if (verbose) System.out.printf("receive chunk: prepare data size is %d%n", size);

                if (tcp) {
                    byte[] dataRecv = data.length >= (8 + size)
                            ? Arrays.copyOfRange(data, 8, data.length)
                            : concat(Arrays.copyOfRange(data, 8, data.length), recvBytes(size + 32));

                    TcpResult result = receiveTcpData(dataRecv, size);
                    chunks.add(result.payload);

                    byte[] ack = result.payload.length < 16
                            ? concat(result.remainder, recvBytes(16))
                            : result.remainder;

                    if (ack.length < 16) {
                        if (verbose) System.out.printf("trying to complete broken ACK %d /16%n", ack.length);
                        ack = concat(ack, recvBytes(16 - ack.length));
                    }

                    if (testTcpTop(ack) == 0) {
                        if (verbose) System.out.println("invalid chunk tcp ACK OK");
                        return null;
                    }

                    int responseCode = (int) unpack("HHHH", ack, 8)[0];
                    if (responseCode == DeviceConstants.CMD_ACK_OK) {
                        if (verbose) System.out.println("chunk tcp ACK OK!");
                        return concatAll(chunks);
                    }

                    if (verbose) {
                        System.out.println("bad response " + BinUtils.byteArrayToHex(ack));
                        System.out.println(BinUtils.byteArrayToHex(concatAll(chunks)));
                    }

                    return null;
                }

                while (true) {
                    byte[] packet = recvBytes(1032);
                    int responseCode = (int) unpack("<4H", packet, 0)[0];

                    if (verbose) System.out.printf("# packet response is: %d%n", responseCode);

                    if (responseCode == DeviceConstants.CMD_DATA) {
                        chunks.add(Arrays.copyOfRange(packet, 8, packet.length));
                        size -= 1024;
                    } else if (responseCode == DeviceConstants.CMD_ACK_OK) {
                        break;
                    } else {
                        if (verbose) System.out.println("broken!");
                        break;
                    }

                    if (verbose) System.out.printf("still needs %d%n", size);
                }

                return concatAll(chunks);
            } else {
                if (verbose) System.out.printf("invalid response %d%n", response);
                return null;
            }
        }

        private byte[] concat(byte[] a, byte[] b) {
            byte[] result = new byte[a.length + b.length];
            System.arraycopy(a, 0, result, 0, a.length);
            System.arraycopy(b, 0, result, a.length, b.length);
            return result;
        }

        private byte[] concatAll(List<byte[]> chunks) {
            int total = chunks.stream().mapToInt(c -> c.length).sum();
            byte[] result = new byte[total];
            int pos = 0;
            for (byte[] chunk : chunks) {
                System.arraycopy(chunk, 0, result, pos, chunk.length);
                pos += chunk.length;
            }
            return result;
        }

        private byte[] readChunk(int start, int size) throws IOException, ZKErrorResponse {
            for (int retries = 0; retries < 3; retries++) {
                int command = Const._CMD_READ_BUFFER;
                byte[] commandString = pack("<ii", start, size);
                int responseSize = tcp ? size + 32 : 1024 + 8;

                boolean success = sendCommand(command, commandString, responseSize);
                byte[] data = receiveChunk();

                if (data != null) {
                    return data;
                }
            }
            throw new ZKErrorResponse(String.format("Can't read chunk %d:[%d]", start, size));
        }

        public class ReadBufferResult {
            public final byte[] data;
            public final int size;

            public ReadBufferResult(byte[] data, int size) {
                this.data = data;
                this.size = size;
            }
        }

        public ReadBufferResult readWithBuffer(int command, int fct, int ext) throws IOException, ZKErrorResponse {
            int MAX_CHUNK = tcp ? 0xFFc0 : 16 * 1024;
            byte[] commandString = pack("<bhii", 1, command, fct, ext);
            if (verbose) System.out.println("rwb cs: " + Arrays.toString(commandString));

            int responseSize = 1024;
            int start = 0;
            List<byte[]> chunks = new ArrayList<>();

            boolean success = sendCommand(Const._CMD_PREPARE_BUFFER, commandString, responseSize);
            if (!success) throw new ZKErrorResponse("RWB Not supported");

            if (responseCode == Const.CMD_DATA) {
                if (tcp) {
                    if (verbose) System.out.printf("DATA! is %d bytes, tcp length is %d%n", data.length, tcpLength);
                    if (data.length < (tcpLength - 8)) {
                        int need = (tcpLength - 8) - data.length;
                        if (verbose) System.out.printf("need more data: %d%n", need);
                        byte[] more = receiveRawData(need);
                        return new ReadBufferResult(concat(data, more), data.length + more.length);
                    } else {
                        if (verbose) System.out.println("Enough data");
                        return new ReadBufferResult(data, data.length);
                    }
                } else {
                    return new ReadBufferResult(data, data.length);
                }
            }

            int size = (int) unpack("I", data, 1)[0];
            if (verbose) System.out.printf("size will be %d%n", size);

            int remain = size % MAX_CHUNK;
            int packets = (size - remain) / MAX_CHUNK;
            if (verbose) System.out.printf("rwb: #%d packets of max %d bytes, and extra %d bytes remain%n", packets, MAX_CHUNK, remain);

            for (int i = 0; i < packets; i++) {
                chunks.add(readChunk(start, MAX_CHUNK));
                start += MAX_CHUNK;
            }
            if (remain > 0) {
                chunks.add(readChunk(start, remain));
                start += remain;
            }

            freeData();
            if (verbose) System.out.printf("_read w/chunk %d bytes%n", start);
            return new ReadBufferResult(concatAll(chunks), start);
        }

        public List<Attendance> getAttendance() throws IOException, ZKErrorResponse {
            readSizes();
            if (records == 0) return new ArrayList<>();

            List<User> users = getUsers();
            if (verbose) System.out.println(users);

            List<Attendance> attendances = new ArrayList<>();
            ReadBufferResult result = readWithBuffer(Const.CMD_ATTLOG_RRQ);
            byte[] attendanceData = result.data;
            int size = result.size;

            if (size < 4) {
                if (verbose) System.out.println("WRN: no attendance data");
                return new ArrayList<>();
            }

            int totalSize = (int) unpack("I", attendanceData, 0)[0];
            int recordSize = totalSize / records;
            if (verbose) System.out.println("record_size is " + recordSize);

            attendanceData = Arrays.copyOfRange(attendanceData, 4, attendanceData.length);

            while (attendanceData.length >= recordSize) {
                Attendance attendance = null;

                if (recordSize == 8) {
                    Object[] fields = unpack("HB4sB", attendanceData, 0);
                    int uid = (int) fields[0];
                    int status = (int) fields[1];
                    byte[] timestampRaw = (byte[]) fields[2];
                    int punch = (int) fields[3];

                    String userId = users.stream().filter(u -> u.uid == uid).map(u -> u.userId).findFirst().orElse(String.valueOf(uid));
                    LocalDateTime timestamp = decodeTime(timestampRaw);
                    attendance = new Attendance(userId, timestamp, status, punch, uid);
                    attendanceData = Arrays.copyOfRange(attendanceData, 8, attendanceData.length);

                } else if (recordSize == 16) {
                    Object[] fields = unpack("<I4sBB2sI", attendanceData, 0);
                    String userId = String.valueOf(fields[0]);
                    byte[] timestampRaw = (byte[]) fields[1];
                    int status = (int) fields[2];
                    int punch = (int) fields[3];

                    Optional<User> match = users.stream().filter(u -> u.userId.equals(userId)).findFirst();
                    int uid = match.map(u -> u.uid).orElse(Integer.parseInt(userId));
                    userId = match.map(u -> u.userId).orElse(userId);

                    LocalDateTime timestamp = decodeTime(timestampRaw);
                    attendance = new Attendance(userId, timestamp, status, punch, uid);
                    attendanceData = Arrays.copyOfRange(attendanceData, 16, attendanceData.length);

                } else {
                    Object[] fields = unpack("<H24sB4sB8s", attendanceData, 0);
                    int uid = (int) fields[0];
                    String userId = new String((byte[]) fields[1]).split("\0")[0];
                    int status = (int) fields[2];
                    byte[] timestampRaw = (byte[]) fields[3];
                    int punch = (int) fields[4];

                    LocalDateTime timestamp = decodeTime(timestampRaw);
                    attendance = new Attendance(userId, timestamp, status, punch, uid);
                    attendanceData = Arrays.copyOfRange(attendanceData, recordSize, attendanceData.length);
                }

                if (attendance != null) {
                    attendances.add(attendance);
                }
            }

            return attendances;
        }

        public boolean clearAttendance() throws Exception {
            int command = DeviceConstants.CMD_CLEAR_ATTLOG;
            boolean success = sendCommand(command);

            if (success) {
                return true;
            } else {
                throw new ZKErrorResponse("Can't clear response");
            }
        }
    }
}
