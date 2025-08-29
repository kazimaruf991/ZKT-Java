import com.kmmaruf.zktjava.Base;

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
        } catch (Exception e) {
//            System.out.println(e.toString());
            e.printStackTrace();
        }

    }
}