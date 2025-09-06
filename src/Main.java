import com.kmmaruf.zktjava.Base;
import com.kmmaruf.zktjava.User;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main {
    public static void main(String[] args) {
        Base base = new Base();
        Base.ZK zk = base.new ZK("203.82.206.78", 43107, 102159);
        //Base.ZK zk = base.new ZK("192.168.34.11", 43107, 102159);
        try {
            System.out.println("Connecting to device...");
            zk.connect();
            System.out.println("SDK build=1      : " + zk.setSdkBuild1());
            System.out.println("Disabling device ...");
            zk.disableDevice();
            int fmt = zk.getExtendFmt();
            System.out.println ("ExtendFmt        : " + fmt);
            fmt = zk.getUserExtendFmt();
            System.out.println ("UsrExtFmt        : " + fmt);
            System.out.println ("Face FunOn       : " + zk.getFaceFunOn());
            System.out.println ("Face Version     : " + zk.getFaceVersion());
            System.out.println ("Finger Version   : " + zk.getFpVersion());
            System.out.println ("Old Firm compat  : " + zk.getCompatOldFirmware());
            Map<String, String>  networkParams = zk.getNetworkParams();
            if (networkParams != null){
                System.out.println(networkParams.toString());
            }else {
                System.out.println("Can't get network param from device");
            }

            LocalDateTime machineDateTime = zk.getTime();
            System.out.println("Machine Time      : " + machineDateTime.toString());

            System.out.println ("Firmware Version : " + zk.getFirmwareVersion());
            System.out.println ("Platform         : " + zk.getPlatform());
            System.out.println ("DeviceName       : " + zk.getDeviceName());
            System.out.println ("Pin Width        : " + zk.getPinWidth());
            System.out.println ("Serial Number    : " + zk.getSerialNumber());
            System.out.println ("MAC              : " + zk.getMac());
            System.out.println (" ");
            System.out.println ("--- sizes & capacity ---");
            zk.readSizes();
            System.out.println (zk);
            System.out.println (" ");
            System.out.println("Getting Users: ------------");
            double startTime = System.currentTimeMillis() / 1000.0;
            List<User> userList = zk.getUsers();
            double endTime = System.currentTimeMillis() / 1000.0;
            System.out.printf("    took %.3f[s]%n", endTime - startTime);
            if (userList.isEmpty()){
                System.out.println("---- No user found!----");
            }else {
                for (User user : userList){
                    if (user != null){
                        System.out.println(user);
                    }
                }
            }
            System.out.println("---------------------------");


            System.out.println("Enabling device....");
            zk.enableDevice();
            zk.disconnect();
            System.out.println("Device disconnected!");


        } catch (Exception e) {
//            System.out.println(e.toString());
            e.printStackTrace();
        }

    }
}