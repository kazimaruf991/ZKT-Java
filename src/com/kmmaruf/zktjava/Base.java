package com.kmmaruf.zktjava;

import com.kmmaruf.zktjava.exceptions.ZKErrorConnection;
import com.kmmaruf.zktjava.exceptions.ZKErrorResponse;
import com.kmmaruf.zktjava.exceptions.ZKNetworkError;

import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.util.Map;

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

        //Will be start from:  def unlock(self, time=3):
    }
}
