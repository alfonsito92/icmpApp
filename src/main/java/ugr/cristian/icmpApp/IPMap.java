package ugr.cristian.icmpApp;

import org.opendaylight.controller.sal.core.NodeConnector;
import java.net.InetAddress;

public class IPMap {
    private InetAddress addr;
    private long macAddr;
    private NodeConnector nodeConnector;
    // ctors, getters, etc.

    public IPMap(InetAddress tempIP, long mac, NodeConnector connector){

      addr=tempIP;
      macAddr=mac;
      nodeConnector=connector;

    }
}
