import com.kmmaruf.zktjava.Base;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main {
    public static void main(String[] args) {
        Base base = new Base();
        Base.ZK zk = base.new ZK("203.82.206.78", 43107, 102159);
        try {
            zk.connect();
        } catch (Exception e) {
            System.out.println(e.toString());
        }

    }
}