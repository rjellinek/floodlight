package edu.wisc.cs.bootcamp.sdn.learningswitch;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.util.U16;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IListener.Command;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;

public class LearningSwitch implements IOFMessageListener, IFloodlightModule {

	protected IFloodlightProviderService floodlightProvider;
	protected static Logger logger;
	protected HashMap<Long, Short> lookupTable = new HashMap<Long, Short>();
    protected static short FLOWMOD_DEFAULT_IDLE_TIMEOUT = 20; // in seconds
    protected static short FLOWMOD_DEFAULT_HARD_TIMEOUT = 0; // infinite
	
	@Override
	public String getName() {
		return "LearningSwtich";
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = 
					new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		logger = LoggerFactory.getLogger(LearningSwitch.class);
	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		logger.info("Receive a packet");

		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		
		if (eth.getEtherType() != Ethernet.TYPE_IPv4)
			return Command.CONTINUE;
		
		switch (msg.getType()) {
			case PACKET_IN:
				logger.debug("Received a packet!");
				
				IPv4 ip = (IPv4)eth.getPayload();
				
				// Check if pkt is UDP; if so, install rule to drop it
				// 0x11 is UDP protocol.
				if (ip.getProtocol() == 0x11) {
					installRuleDropPacket(sw, (OFPacketIn)msg);
				}	
				
				/* Store MAC:port info from incoming packet */
				long src_mac = eth.getSourceMAC().toLong();
				
				// If our lookupTable doesn't have the entry for this incoming 
				// MAC addr, then add it
				if (!lookupTable.containsKey(src_mac)) {
					short in_port = ((OFPacketIn)msg).getInPort();
					lookupTable.put(src_mac, in_port);
				}
				
				// If we have an entry for the outgoing MAC addr, then
				// send to the corresponding port. Otherwise set out_port to
				// -1 so we know to flood it below.
				long dest_mac = eth.getDestinationMAC().toLong();
				short out_port = -1;
				if (lookupTable.containsKey(dest_mac)) {
					out_port = lookupTable.get(dest_mac);
				}
				
				OFActionOutput action = null;
				/* Send to out_port we have saved in lookupTable */
				if (out_port > 0) {
					action = new OFActionOutput().setPort(out_port);
				}
				/* Flood packet */
				else { 
			        action = new OFActionOutput().setPort((short) OFPort.OFPP_FLOOD.getValue());
				}
				
				/* THE REST HERE IS FROM Hub.java */
		        OFPacketIn pi = (OFPacketIn) msg;
		        /* I need a packet out message--need to tell switch what to do -rdj */
		        /* You can say "I only want the X bits of this packet to be forwarded to the controller for 
		         * analysis. Which is cool, but the rest of the packet needs to sit in the switch buffer while
		         * it waits for the controller to process the packet. Switch hangs on to whole packet. Controller
		         * doesn't need to see the whole packet. But needs to provide hint to the switch re: what packet out is.
		         * 
		         * As a hub, the action should be to flood the packet. So the action is OFPP_FLOOD below.
		         * 
		         */
		        OFPacketOut po = (OFPacketOut) floodlightProvider.getOFMessageFactory()
		                .getMessage(OFType.PACKET_OUT);
		        po.setBufferId(pi.getBufferId())
		            .setInPort(pi.getInPort());
		
		        // set actions
		        po.setActions(Collections.singletonList((OFAction)action));
		        po.setActionsLength((short) OFActionOutput.MINIMUM_LENGTH);
		
		        /* If we didn't get a buffer ID then we know the controller has the whole packet, and the switch doesn't have it.
		        * So the controller needs to send the whole packet back to the switch. -rdj
		        */
		        // set data if is is included in the packetin
		        if (pi.getBufferId() == 0xffffffff) {
		            byte[] packetData = pi.getPacketData();
		            po.setLength(U16.t(OFPacketOut.MINIMUM_LENGTH
		                    + po.getActionsLength() + packetData.length));
		            po.setPacketData(packetData);
		        } else {
		            po.setLength(U16.t(OFPacketOut.MINIMUM_LENGTH
		                    + po.getActionsLength()));
		        }
		        try {
		        	// send this message to the switch
		            sw.write(po, cntx);
		        } catch (IOException e) {
		            logger.error("Failure writing PacketOut", e);
		        }

			default:
				break;
		
		}
		return Command.CONTINUE;
	}

	
	/*
	 * push a packet-out to the switch
	 * */
	private void pushPacket(IOFSwitch sw, OFMatch match, OFPacketIn pi, short outport) {
		
		// create an OFPacketOut for the pushed packet
        OFPacketOut po = (OFPacketOut) floodlightProvider.getOFMessageFactory()
                		.getMessage(OFType.PACKET_OUT);        
        
        // update the inputPort and bufferID
        po.setInPort(pi.getInPort());
        po.setBufferId(pi.getBufferId());
                
        // define the actions to apply for this packet
        OFActionOutput action = new OFActionOutput();
		action.setPort(outport);		
		po.setActions(Collections.singletonList((OFAction)action));
		po.setActionsLength((short)OFActionOutput.MINIMUM_LENGTH);
	        
        // set data if it is included in the packet in but buffer id is NONE
        if (pi.getBufferId() == OFPacketOut.BUFFER_ID_NONE) {
            byte[] packetData = pi.getPacketData();
            po.setLength(U16.t(OFPacketOut.MINIMUM_LENGTH
                    + po.getActionsLength() + packetData.length));
            po.setPacketData(packetData);
        } else {
            po.setLength(U16.t(OFPacketOut.MINIMUM_LENGTH
                    + po.getActionsLength()));
        }        
        
        // push the packet to the switch
        try {
            sw.write(po, null);
        } catch (IOException e) {
            logger.error("failed to write packetOut: ", e);
        }
	}
	
	/**
	 * 
	 * @param eth
	 * 
	 * Install a rule to drop UDP packets
	 * @return 
	 */
	private net.floodlightcontroller.core.IListener.Command installRuleDropPacket(IOFSwitch sw, OFPacketIn pi) {
		
        // Read in packet data headers by using an OFMatch structure
        OFMatch match = new OFMatch();
        match.loadFromPacket(pi.getPacketData(), pi.getInPort());
        		            
    	// create the rule and specify it's an ADD rule
    	OFFlowMod rule = new OFFlowMod();
		rule.setType(OFType.FLOW_MOD); 			
		rule.setCommand(OFFlowMod.OFPFC_ADD);
		// specify that all fields except destMac to be wildcarded
		match.setWildcards(~OFMatch.OFPFW_NW_PROTO);
		match.setDataLayerDestination(match.getDataLayerDestination());
		rule.setMatch(match);
		
		// specify timers for the life of the rule
		rule.setIdleTimeout(LearningSwitch.FLOWMOD_DEFAULT_IDLE_TIMEOUT);
		rule.setHardTimeout(LearningSwitch.FLOWMOD_DEFAULT_HARD_TIMEOUT);
        
        // set the buffer id to NONE - implementation artifact
		rule.setBufferId(OFPacketOut.BUFFER_ID_NONE);

        // set of actions to apply to this rule
		/*//No action for DROP
		ArrayList<OFAction> actions = new ArrayList<OFAction>();
		OFAction outputTo = new OFActionOutput(outPort);
		actions.add(outputTo);
		rule.setActions(actions);
		*/
		 			
		// specify the length of the flow structure created
		//rule.setLength((short) (OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH)); 
		rule.setLength((short)OFFlowMod.MINIMUM_LENGTH); 			

		logger.debug("install rule to drop UDP packet");
		
		try {
			sw.write(rule, null);
		} catch (Exception e) {
			e.printStackTrace();
		}
        
        // push the packet to the switch	
        	this.pushPacket(sw, match, pi, outPort);        	
        }       

	}

}
