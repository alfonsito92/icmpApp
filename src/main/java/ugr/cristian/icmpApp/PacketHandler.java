/**
Copyright (C) 2015  Cristian Alfonso Prieto Sánchez

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

package ugr.cristian.icmpApp;

import java.util.ArrayList;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.LinkedList;
import java.util.List;
import java.util.Iterator;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;


import org.opendaylight.controller.sal.action.Action;
import org.opendaylight.controller.sal.action.Output;
import org.opendaylight.controller.sal.action.SetDlDst;
import org.opendaylight.controller.sal.action.SetDlSrc;
import org.opendaylight.controller.sal.action.SetNwDst;
import org.opendaylight.controller.sal.action.SetNwSrc;
import org.opendaylight.controller.sal.core.ConstructionException;
import org.opendaylight.controller.sal.core.Node;
import org.opendaylight.controller.sal.core.Edge;
import org.opendaylight.controller.sal.core.Path;
import org.opendaylight.controller.sal.core.Property;
import org.opendaylight.controller.sal.core.NodeConnector;
import org.opendaylight.controller.sal.flowprogrammer.Flow;
import org.opendaylight.controller.sal.flowprogrammer.IFlowProgrammerService;
import org.opendaylight.controller.sal.match.Match;
import org.opendaylight.controller.sal.match.MatchType;
import org.opendaylight.controller.sal.packet.BitBufferHelper;
import org.opendaylight.controller.sal.packet.Ethernet;
import org.opendaylight.controller.sal.packet.IDataPacketService;
import org.opendaylight.controller.sal.packet.IListenDataPacket;
import org.opendaylight.controller.sal.packet.IPv4;
import org.opendaylight.controller.sal.packet.ICMP;
import org.opendaylight.controller.sal.packet.Packet;
import org.opendaylight.controller.sal.packet.PacketResult;
import org.opendaylight.controller.sal.packet.RawPacket;
import org.opendaylight.controller.sal.packet.TCP;
import org.opendaylight.controller.sal.reader.NodeConnectorStatistics;
import org.opendaylight.controller.sal.utils.EtherTypes;
import org.opendaylight.controller.sal.utils.IPProtocols;
import org.opendaylight.controller.sal.utils.Status;
import org.opendaylight.controller.switchmanager.ISwitchManager;
import org.opendaylight.controller.topologymanager.ITopologyManager;
import org.opendaylight.controller.statisticsmanager.IStatisticsManager;

import ugr.cristian.routeFinder.routeImp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PacketHandler implements IListenDataPacket {

    private static final Logger log = LoggerFactory.getLogger(PacketHandler.class);

    private IDataPacketService dataPacketService;
    routeImp implementationRoute = new routeImp();
    private ISwitchManager switchManager;
    private IFlowProgrammerService flowProgrammerService;
    private Map<InetAddress, NodeConnector> listIP = new HashMap<InetAddress, NodeConnector>();



    short idle = 30;
    short hard = 60;

    static private InetAddress intToInetAddress(int i) {
        byte b[] = new byte[] { (byte) ((i>>24)&0xff), (byte) ((i>>16)&0xff), (byte) ((i>>8)&0xff), (byte) (i&0xff) };
        InetAddress addr;
        try {
            addr = InetAddress.getByAddress(b);
        } catch (UnknownHostException e) {
            return null;
        }

        return addr;
    }


    /**
     * Sets a reference to the requested DataPacketService
     */
    void setDataPacketService(IDataPacketService s) {
        log.trace("Set DataPacketService.");

        dataPacketService = s;
    }

    /**
     * Unsets DataPacketService
     */
    void unsetDataPacketService(IDataPacketService s) {
        log.trace("Removed DataPacketService.");

        if (dataPacketService == s) {
            dataPacketService = null;
        }
    }



    /**
     * Sets a reference to the requested SwitchManagerService
     */
    void setSwitchManagerService(ISwitchManager s) {
        log.trace("Set SwitchManagerService.");

        switchManager = s;
    }

    /**
     * Unsets SwitchManagerService
     */
    void unsetSwitchManagerService(ISwitchManager s) {
        log.trace("Removed SwitchManagerService.");

        if (switchManager == s) {
            switchManager = null;
        }
    }

    /**
     * Sets a reference to the requested FlowProgrammerService
     */
    void setFlowProgrammerService(IFlowProgrammerService s) {
        log.trace("Set FlowProgrammerService.");

        flowProgrammerService = s;
    }

    /**
     * Unsets FlowProgrammerService
     */
    void unsetFlowProgrammerService(IFlowProgrammerService s) {
        log.trace("Removed FlowProgrammerService.");

        if (flowProgrammerService == s) {
            flowProgrammerService = null;
        }
    }


    @Override
    public PacketResult receiveDataPacket(RawPacket inPkt) {
        // The connector, the packet came from ("port")
        NodeConnector ingressConnector = inPkt.getIncomingNodeConnector();
        // The node that received the packet ("switch")
        Node node = ingressConnector.getNode();

        ///////////////////////
        implementationRoute.init();

        //log.trace("Packet from " + node.getNodeIDString() + " " + ingressConnector.getNodeConnectorIDString());

        // Use DataPacketService to decode the packet.
        Packet pkt = dataPacketService.decodeDataPacket(inPkt);

        if (pkt instanceof Ethernet) {

            Ethernet ethFrame = (Ethernet) pkt;
            byte[] srcMAC_B = (ethFrame).getSourceMACAddress();
            long srcMAC = BitBufferHelper.toNumber(srcMAC_B);
            Object l3Pkt = ethFrame.getPayload();

            if (l3Pkt instanceof IPv4) {
                IPv4 ipv4Pkt = (IPv4) l3Pkt;
                InetAddress orgAddr = intToInetAddress(ipv4Pkt.getSourceAddress());
                InetAddress dstAddr = intToInetAddress(ipv4Pkt.getDestinationAddress());
                Object l4Datagram = ipv4Pkt.getPayload();

                learnSourceIP(orgAddr, ingressConnector);

                if (l4Datagram instanceof ICMP) {
                  ICMP icmpDatagram = (ICMP) l4Datagram;

                  NodeConnector egressConnector = getOutConnector(dstAddr);
                  if(egressConnector==null){

                    floodPacket(inPkt);

                  } else{

                    /**************************Pruebas Dijkstra*********************/

                    Path result = implementationRoute.getRoute(ingressConnector.getNode(), egressConnector.getNode());
                    if(result==null)
                    log.trace("Obtenido el path gracias a Dijkstra: " + result);
                    else
                    log.trace("Lo que devuelve es nulo");

                    /**************************************************************/
                    
                    if(  programFlow( orgAddr, dstAddr, egressConnector, node) ){
                      log.trace("Flujo instalado correctamente en el nodo " + node + " por el puerto " + egressConnector);
                    }
                    else{
                      log.trace("Error instalando el flujo");
                    }

                    inPkt.setOutgoingNodeConnector(egressConnector);
                    this.dataPacketService.transmitDataPacket(inPkt);

                  }

                  return PacketResult.CONSUME;

                }
              }
            }
            // We did not process the packet -> let someone else do the job.
            return PacketResult.IGNORED;
    }

    private void floodPacket(RawPacket inPkt) {
        NodeConnector incoming_connector = inPkt.getIncomingNodeConnector();
        Node incoming_node = incoming_connector.getNode();

        Set<NodeConnector> nodeConnectors =
                this.switchManager.getUpNodeConnectors(incoming_node);

                for (NodeConnector p : nodeConnectors) {
                    if (!p.equals(incoming_connector)) {
                      try {
                        RawPacket destPkt = new RawPacket(inPkt);
                        destPkt.setOutgoingNodeConnector(p);
                        this.dataPacketService.transmitDataPacket(destPkt);
                    } catch (ConstructionException e2) {
                        continue;
                    }
                }
            }
        }

    private boolean programFlow(InetAddress orgAddr, InetAddress dstAddr, NodeConnector outConnector, Node node) {

        Match match = new Match();
        match.setField(MatchType.DL_TYPE, (short) 0x0800);  // IPv4 ethertype
        match.setField(MatchType.NW_PROTO, IPProtocols.ICMP.byteValue());
        match.setField(MatchType.NW_SRC, orgAddr);
        match.setField(MatchType.NW_DST, dstAddr);

        List<Action> actions = new ArrayList<Action>();
        actions.add(new Output(outConnector));

        Flow f = new Flow(match, actions);

        // Create the flow
        Flow flow = new Flow(match, actions);

        flow.setIdleTimeout(idle);
        flow.setHardTimeout(hard);

        // Use FlowProgrammerService to program flow.
        Status status = flowProgrammerService.addFlowAsync(node, flow);
        if (!status.isSuccess()) {
            log.error("Could not program flow: " + status.getDescription());
            return false;
        }
        else{
        return true;
      }

    }

    private void learnSourceIP(InetAddress srcIP, NodeConnector ingressConnector) {

      this.listIP.put(srcIP, ingressConnector);

    }

    private NodeConnector getOutConnector(InetAddress orgAddress) {

        return this.listIP.get(orgAddress);
    }

}
