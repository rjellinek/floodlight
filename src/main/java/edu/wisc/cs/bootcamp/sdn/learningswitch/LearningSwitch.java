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
import org.openflow.protocol.action.OFActionTransportLayerDestination;
import org.openflow.protocol.action.OFActionTransportLayerSource;
import org.openflow.util.U16;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;


/*	
 * since we are listening to OpenFlow messages we need to 
 * register with the FloodlightProvider (IFloodlightProviderService class
*/
public class LearningSwitch implements IOFMessageListener, IFloodlightModule, IOFSwitchListener {

	/*
	 * member variables used in LearningSwitch
	 * */
	protected IFloodlightProviderService floodlightProvider;
	protected Map<Long, Short> macToPort;
	protected static Logger logger;
	
	// 0 - NOTHING, 1 - HUB, 2 - LEARNING_SWITCH_WO_RULES, 3 - LEARNING_SWITCH_WITH_RULES
	// 4 - LEARNING_SWITCH_WITH_FIREWALL, 5 - LEARNING_SWITCH_WITH_NAT
	protected static int CTRL_LEVEL = 5;
    protected static short FLOWMOD_DEFAULT_IDLE_TIMEOUT = 20; // in seconds
    protected static short FLOWMOD_DEFAULT_HARD_TIMEOUT = 0; // infinite
	
	/*
	 * important to override 
	 * put an ID for our OFMessage listener
	 * */
	@Override
	public String getName() {
		return LearningSwitch.class.getSimpleName();
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

	/*
	 * important to override 
	 * need to wire up to the module loading system by telling the 
	 * module loader we depend on it 
	 * */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService >> fsrv = 
			new ArrayList<Class<? extends IFloodlightService>>();
		fsrv.add(IFloodlightProviderService.class);
		return fsrv;
	}

	/*
	 * important to override 
	 * load dependencies and initialize datastructures
	 * */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		macToPort 		   = new HashMap<Long, Short>();
		logger    		   = LoggerFactory.getLogger(LearningSwitch.class);
	}

	/*
	 * important to override 
	 * implement the basic listener - listen for PACKET_IN messages
	 * */
	@Override
	public void startUp(FloodlightModuleContext context) {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		floodlightProvider.addOFSwitchListener(this);
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
	
	/*
	 * push a packet-out to the switch
	 * */
	private void pushPacketRemap(IOFSwitch sw, OFMatch match, OFPacketIn pi, short outport) {
		
		// create an OFPacketOut for the pushed packet
        OFPacketOut po = (OFPacketOut) floodlightProvider.getOFMessageFactory()
                		.getMessage(OFType.PACKET_OUT);        
        
        // update the inputPort and bufferID
        po.setInPort(pi.getInPort());
        po.setBufferId(pi.getBufferId());
                
        ArrayList<OFAction> actions = new ArrayList<OFAction>();
        
        // define the actions to apply for this packet
        OFActionOutput action = new OFActionOutput();
		action.setPort(outport);
		OFActionTransportLayerDestination remap = new OFActionTransportLayerDestination((short)443);
		
		actions.add(action);
		actions.add(remap);
		
		po.setActions(actions);
		po.setActionsLength((short)(OFActionOutput.MINIMUM_LENGTH + OFActionTransportLayerDestination.MINIMUM_LENGTH));
	        
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
		
	private Command ctrlLogicWithNAT(IOFSwitch sw, OFPacketIn pi) {
        logger.debug("Controller called");

		ArrayList<OFAction> actions = new ArrayList<OFAction>();
		
        // Read in packet data headers by using an OFMatch structure
        OFMatch match = new OFMatch();
        match.loadFromPacket(pi.getPacketData(), pi.getInPort());		
        
		// take the source and destination mac from the packet
		Long sourceMac = Ethernet.toLong(match.getDataLayerSource());
        Long destMac   = Ethernet.toLong(match.getDataLayerDestination());
        
        Short inputPort = pi.getInPort();
        
        // if the (sourceMac, port) does not exist in MAC table
        // 		add a new entry
        if (!macToPort.containsKey(sourceMac)) 
        	macToPort.put(sourceMac, inputPort);
       
        // if the destMac is in the MAC table take the outPort and send it there
        Short outPort = macToPort.get(destMac);
        logger.debug("outPort: {}", outPort);
                
        // TODO: If packet is 80 or 443, remap and install rule
        // Fall through and do Learning Switch rules.
        if (match.getTransportDestination() == (short)80) {
            logger.debug("Installing NAT rule");

 			// specify that all fields except destMac to be wildcarded
 			match.setWildcards(~(OFMatch.OFPFW_DL_TYPE | OFMatch.OFPFW_NW_PROTO | OFMatch.OFPFW_TP_DST | OFMatch.OFPFW_DL_DST));
 			match.setDataLayerType((short)0x0800); // set ethernet
 			match.setNetworkProtocol(IPv4.PROTOCOL_TCP);
 			match.setTransportDestination((short)80);
 			        	
 			// Only insert a rule in the forward direction if we know where to 
        	// forward it 
        	if (outPort != null) {
                logger.debug("Installing NAT rule in forward direction.");

        		OFFlowMod rule = new OFFlowMod();
     			rule.setType(OFType.FLOW_MOD); 			
     			rule.setCommand(OFFlowMod.OFPFC_ADD);
    
     			rule.setMatch(match);
        		
	 			// action: rewrite destination TCP port to 443
	 			OFAction rewrite = new OFActionTransportLayerDestination((short)443);
	 			
	 			// If we have the output port, we add a rule to forward. Otherwise
	 			// we need to flood it to 443 and we can only add the rule to always send 
	 			// out the correct port once we have that port in our table.
	 			OFAction forward = new OFActionOutput(outPort);
	 			
	 			actions.add(rewrite);
	 			actions.add(forward); 
	 			
				rule.setLength((short)(OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH + OFActionTransportLayerDestination.MINIMUM_LENGTH)); 
	 			
	 			rule.setPriority((short)3);
	 			rule.setActions(actions);
	 			
	 	        // set the buffer id to NONE - implementation artifact
	 			rule.setBufferId(OFPacketOut.BUFFER_ID_NONE);
	
	 			try {
	 				sw.write(rule, null);
	 				sw.flush();
	 			} catch (Exception e) {
	 				e.printStackTrace();
	 			}
        	}
        	else {
                logger.debug("Installing NAT rule in reverse direction");

	 			// Now install reverse list with a fresh match
	 			OFFlowMod rule = new OFFlowMod();
	 			actions.clear();
	 			OFMatch reverseMatch = new OFMatch();
	 			//reverseMatch.setWildcards(~(OFMatch.OFPFW_DL_TYPE | OFMatch.OFPFW_NW_PROTO | OFMatch.OFPFW_TP_SRC | OFMatch.OFPFW_TP_DST));
	 			reverseMatch.setWildcards(~(OFMatch.OFPFW_DL_TYPE | OFMatch.OFPFW_NW_PROTO | OFMatch.OFPFW_TP_SRC | OFMatch.OFPFW_DL_DST));
	 			reverseMatch.setDataLayerType((short)0x0800); // set ethernet
	 			reverseMatch.setDataLayerDestination(match.getDataLayerSource());
	 			reverseMatch.setDataLayerSource(match.getDataLayerDestination());
	 			reverseMatch.setNetworkProtocol(IPv4.PROTOCOL_TCP);
	 			reverseMatch.setTransportSource((short)443);
	 			rule.setMatch(reverseMatch);
	 			
	 			// send back to wherever we got it from (high garbage port on netcat), not to 80
	 			//OFAction rewriteDst = new OFActionTransportLayerDestination(match.getTransportSource());
	 			//actions.add(rewriteDst);
	 			
	 			// rewrite TCP src so it looks like pkt is coming from port 80
	 			OFAction rewriteSrc = new OFActionTransportLayerSource((short)80);
	 			actions.add(rewriteSrc);
	 			
	 			// forward to our original input interface
	 			OFAction forward = new OFActionOutput(inputPort);
	 			actions.add(forward);
	 			
	 			rule.setActions(actions);
	 			
				rule.setLength((short)(OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH 
						+ OFActionTransportLayerSource.MINIMUM_LENGTH)); 
	 			rule.setPriority((short)3);
	 			
	 	        // set the buffer id to NONE - implementation artifact
	 			rule.setBufferId(OFPacketOut.BUFFER_ID_NONE);
	 			
				try {
	 				sw.write(rule, null);
	 				sw.flush();
	 			} catch (Exception e) {
	 				e.printStackTrace();
	 			}
        	}
        	
            if (match.getTransportDestination() == (short)80) {
            	this.pushPacketRemap(sw, match, pi, (short)OFPort.OFPP_FLOOD.getValue());
            }
			
 			return Command.CONTINUE;
        }
        
        // if an entry does exist for destMac
        //		flood the packet
        if (outPort == null) 
        	this.pushPacket(sw, match, pi, (short)OFPort.OFPP_FLOOD.getValue());                	
        else {
    	        	
	    	// otherwise install a rule s.t. all the traffic with the destination
	        // destMac should be forwarded on outPort
        		            
        	// create the rule and specify it's an ADD rule
        	OFFlowMod rule = new OFFlowMod();
 			rule.setType(OFType.FLOW_MOD); 			
 			rule.setCommand(OFFlowMod.OFPFC_ADD);
 			
 			// specify that all fields except destMac to be wildcarded
 			match.setWildcards(~OFMatch.OFPFW_DL_DST);
 			//match.setDataLayerDestination(match.getDataLayerDestination());
 			rule.setMatch(match);
 			
 			// specify timers for the life of the rule
 			rule.setIdleTimeout(LearningSwitch.FLOWMOD_DEFAULT_IDLE_TIMEOUT);
 			rule.setHardTimeout(LearningSwitch.FLOWMOD_DEFAULT_HARD_TIMEOUT);
 			rule.setPriority((short)2);
 	        
 	        // set the buffer id to NONE - implementation artifact
 			rule.setBufferId(OFPacketOut.BUFFER_ID_NONE);
 	       
 	        // set of actions to apply to this rule
// 			ArrayList<OFAction> actions = new ArrayList<OFAction>();
 			OFAction outputTo = new OFActionOutput(outPort);
 			actions.add(outputTo);
 			rule.setActions(actions);
 			 			
		    rule.setLength((short)(OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH)); 
 			rule.setPriority((short)3);
 	        
 				
 			logger.debug("install rule for destination {}", destMac);
 			
 			try {
 				sw.write(rule, null);
 			} catch (Exception e) {
 				e.printStackTrace();
 			}	
        
        // push the packet to the switch	
        	this.pushPacket(sw, match, pi, outPort);        	
        }       
        
        return Command.CONTINUE;
	}
	
	private void remapPortsStaticRule(IOFSwitch sw) {
    	logger.debug("Remap port!");
	    // Read in packet data headers by using an OFMatch structure
	    OFMatch match = new OFMatch();
	    //match.loadFromPacket(pi.getPacketData(), pi.getInPort());
     
		// create the rule and specify it's an ADD rule
    	OFFlowMod rule = new OFFlowMod();
		rule.setType(OFType.FLOW_MOD); 			
		rule.setCommand(OFFlowMod.OFPFC_ADD);
				
		// specify that all fields except destMac to be wildcarded
		match.setWildcards(~(OFMatch.OFPFW_NW_PROTO | OFMatch.OFPFW_DL_TYPE | OFMatch.OFPFW_TP_DST));
		match.setDataLayerType((short)0x0800); // set ethernet
		match.setNetworkProtocol(IPv4.PROTOCOL_TCP);
		match.setTransportDestination((short)80);
		rule.setMatch(match);
		
		// specify timers for the life of the rule
		//rule.setIdleTimeout(LearningSwitch.FLOWMOD_DEFAULT_IDLE_TIMEOUT);
		//rule.setHardTimeout(LearningSwitch.FLOWMOD_DEFAULT_HARD_TIMEOUT);
		//rule.setPriority((short)40000);
		rule.setPriority((short)2);
		rule.setIdleTimeout((short)0);
		rule.setHardTimeout((short)0);
        
        // set the buffer id to NONE - implementation artifact
		rule.setBufferId(OFPacketOut.BUFFER_ID_NONE);
		 			
        // set of actions to apply to this rule
		ArrayList<OFAction> actions = new ArrayList<OFAction>();
		OFAction outputTo = new OFActionOutput(OFPort.OFPP_CONTROLLER.getValue());
		actions.add(outputTo);
		rule.setActions(actions);
		 			
		// specify the length of the flow structure created
		rule.setLength((short) (OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));
		
		try {
			sw.write(rule, null);
		} catch (Exception e) {
			e.printStackTrace();
		}	

    // push the packet to the switch	
    //	this.pushPacket(sw, match, pi, match.getDataLayerDestination());   
	}
	
	private void setFirewallRuleUDP(IOFSwitch sw) {
    	logger.debug("Setting Firewall rule to drop UDP!");
	    // Read in packet data headers by using an OFMatch structure
	    OFMatch match = new OFMatch();
	    //match.loadFromPacket(pi.getPacketData(), pi.getInPort());
     
		// create the rule and specify it's an ADD rule
    	OFFlowMod rule = new OFFlowMod();
		rule.setType(OFType.FLOW_MOD); 			
		rule.setCommand(OFFlowMod.OFPFC_ADD);
				
		// specify that all fields except destMac to be wildcarded
		match.setWildcards(~(OFMatch.OFPFW_NW_PROTO | OFMatch.OFPFW_DL_TYPE));
		match.setDataLayerType((short)0x0800); // set ethernet
		match.setNetworkProtocol(IPv4.PROTOCOL_UDP);
		rule.setMatch(match);
		
		// specify timers for the life of the rule
		//rule.setIdleTimeout(LearningSwitch.FLOWMOD_DEFAULT_IDLE_TIMEOUT);
		//rule.setHardTimeout(LearningSwitch.FLOWMOD_DEFAULT_HARD_TIMEOUT);
		rule.setPriority((short)1);
		rule.setIdleTimeout((short)0);
		rule.setHardTimeout((short)0);
        
        // set the buffer id to NONE - implementation artifact
		rule.setBufferId(OFPacketOut.BUFFER_ID_NONE);
		 			
		// specify the length of the flow structure created
		rule.setLength((short) (OFFlowMod.MINIMUM_LENGTH)); 			
				
		try {
			sw.write(rule, null);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private void setFirewallRuleTelnet(IOFSwitch sw) {
    	logger.debug("Setting Firewall rule to drop Telnet!");
	    // Read in packet data headers by using an OFMatch structure
	    OFMatch match = new OFMatch();
	    //match.loadFromPacket(pi.getPacketData(), pi.getInPort());
     
		// create the rule and specify it's an ADD rule
    	OFFlowMod rule = new OFFlowMod();
		rule.setType(OFType.FLOW_MOD); 			
		rule.setCommand(OFFlowMod.OFPFC_ADD);
				
		// specify that all fields except destMac to be wildcarded
		match.setWildcards(~(OFMatch.OFPFW_TP_DST | OFMatch.OFPFW_DL_TYPE | OFMatch.OFPFW_NW_PROTO));
		match.setDataLayerType((short)0x0800); // set ethernet
		match.setNetworkProtocol(IPv4.PROTOCOL_TCP);
		match.setTransportDestination((short)23);
		rule.setMatch(match);
		
		// specify timers for the life of the rule
		//rule.setIdleTimeout(LearningSwitch.FLOWMOD_DEFAULT_IDLE_TIMEOUT);
		//rule.setHardTimeout(LearningSwitch.FLOWMOD_DEFAULT_HARD_TIMEOUT);
		rule.setPriority((short)1);
		rule.setIdleTimeout((short)0);
		rule.setHardTimeout((short)0);
        
        // set the buffer id to NONE - implementation artifact
		rule.setBufferId(OFPacketOut.BUFFER_ID_NONE);
		 			
		// specify the length of the flow structure created
		rule.setLength((short) (OFFlowMod.MINIMUM_LENGTH)); 			
			
		logger.debug("install rule for Firewall");
		
		try {
			sw.write(rule, null);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	/*
	 * control logic which install static rules 
	 * */
	private Command ctrlLogicWithFirewall(IOFSwitch sw, OFPacketIn pi) {
		
		
	    // Read in packet data headers by using an OFMatch structure
        OFMatch match = new OFMatch();
        match.loadFromPacket(pi.getPacketData(), pi.getInPort());
        
        logger.debug("match.getNetworkProtocol == {}", match.getNetworkProtocol());
        
		// take the source and destination mac from the packet
		Long sourceMac = Ethernet.toLong(match.getDataLayerSource());
        Long destMac   = Ethernet.toLong(match.getDataLayerDestination());
        
        Short inputPort = pi.getInPort();
        
        // if the (sourceMac, port) does not exist in MAC table
        // 		add a new entry
        if (!macToPort.containsKey(sourceMac)) 
        	macToPort.put(sourceMac, inputPort);
       
        // if the destMac is in the MAC table take the outPort and send it there
        Short outPort = macToPort.get(destMac);
        
        // if an entry does exist for destMac
        //		flood the packet
        if (outPort == null) 
        	this.pushPacket(sw, match, pi, (short)OFPort.OFPP_FLOOD.getValue());                	
        else {
    	        	
    	// otherwise install a rule s.t. all the traffic with the destination
        // destMac should be forwarded on outPort
        		            
        	// create the rule and specify it's an ADD rule
        	OFFlowMod rule = new OFFlowMod();
 			rule.setType(OFType.FLOW_MOD); 			
 			rule.setCommand(OFFlowMod.OFPFC_ADD);
 			rule.setPriority((short)1);
 			
 			/* XXX: 
 			 * So right now, we're wildcarding the NW_PROTO, which means we'll have
 			 * O(#protocols * #ports) rules. Ideally, we'd be able to create one rule
 			 * for each outgoing port that says "send the pkt destined for port P out
 			 * port P, UNLESS IT'S UDP." Right now, we need to make rules saying "if
 			 * pkt is destined for port P and is TCP, send it out; if pkt is destined
 			 * for port P and is ICMP, send it out; if pkt is destined for port P and is
 			 * protocol XYZ, send it out". We'd have possibly rules for every one of 
 			 * these except UDP, since UDP packets sent to this controller would 
 			 * hit the getNetworkProtocol()==17 match above and the rule would be installed
 			 * to drop UDP packets.
 			 */
 			// specify that all fields except destMac to be wildcarded
 			match.setWildcards(~(OFMatch.OFPFW_NW_PROTO | OFMatch.OFPFW_DL_TYPE | OFMatch.OFPFW_DL_DST));
 			match.setDataLayerType((short)0x0800); // set ethernet
// 			match.setNetworkTypeOfService(match.getNetworkTypeOfService());
 			//match.setNetworkProtocol(match.getNetworkProtocol());
 			match.setDataLayerDestination(match.getDataLayerDestination());
 			rule.setMatch(match);
 			
 			// specify timers for the life of the rule
 			rule.setIdleTimeout(LearningSwitch.FLOWMOD_DEFAULT_IDLE_TIMEOUT);
 			rule.setHardTimeout(LearningSwitch.FLOWMOD_DEFAULT_HARD_TIMEOUT);
 	        
 	        // set the buffer id to NONE - implementation artifact
 			rule.setBufferId(OFPacketOut.BUFFER_ID_NONE);
 	       
 	        // set of actions to apply to this rule
 			ArrayList<OFAction> actions = new ArrayList<OFAction>();
 			OFAction outputTo = new OFActionOutput(outPort);
 			actions.add(outputTo);
 			rule.setActions(actions);
 			 			
 			// specify the length of the flow structure created
 			rule.setLength((short) (OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH)); 			
 				
 			logger.debug("install rule for destination {}", destMac);
 			
 			try {
 				sw.write(rule, null);
 			} catch (Exception e) {
 				e.printStackTrace();
 			}	
        
        // push the packet to the switch	
        	this.pushPacket(sw, match, pi, outPort);        	
        }       
        
        return Command.CONTINUE;
	}

	
	
	
	/*
	 * control logic which install static rules 
	 * */
	private Command ctrlLogicWithRules(IOFSwitch sw, OFPacketIn pi) {
		
        // Read in packet data headers by using an OFMatch structure
        OFMatch match = new OFMatch();
        match.loadFromPacket(pi.getPacketData(), pi.getInPort());		
        
		// take the source and destination mac from the packet
		Long sourceMac = Ethernet.toLong(match.getDataLayerSource());
        Long destMac   = Ethernet.toLong(match.getDataLayerDestination());
        
        Short inputPort = pi.getInPort();
        
        // if the (sourceMac, port) does not exist in MAC table
        // 		add a new entry
        if (!macToPort.containsKey(sourceMac)) 
        	macToPort.put(sourceMac, inputPort);
        
       
        // if the destMac is in the MAC table take the outPort and send it there
        Short outPort = macToPort.get(destMac);
        
        // if an entry does exist for destMac
        //		flood the packet
        if (outPort == null) 
        	this.pushPacket(sw, match, pi, (short)OFPort.OFPP_FLOOD.getValue());                	
        else {
    	        	
    	// otherwise install a rule s.t. all the traffic with the destination
        // destMac should be forwarded on outPort
        		            
        	// create the rule and specify it's an ADD rule
        	OFFlowMod rule = new OFFlowMod();
 			rule.setType(OFType.FLOW_MOD); 			
 			rule.setCommand(OFFlowMod.OFPFC_ADD);
 			
 			// specify that all fields except destMac to be wildcarded
 			match.setWildcards(~OFMatch.OFPFW_DL_DST);
 			//match.setDataLayerDestination(match.getDataLayerDestination());
 			rule.setMatch(match);
 			
 			// specify timers for the life of the rule
 			rule.setIdleTimeout(LearningSwitch.FLOWMOD_DEFAULT_IDLE_TIMEOUT);
 			rule.setHardTimeout(LearningSwitch.FLOWMOD_DEFAULT_HARD_TIMEOUT);
 	        
 	        // set the buffer id to NONE - implementation artifact
 			rule.setBufferId(OFPacketOut.BUFFER_ID_NONE);
 	       
 	        // set of actions to apply to this rule
 			ArrayList<OFAction> actions = new ArrayList<OFAction>();
 			OFAction outputTo = new OFActionOutput(outPort);
 			actions.add(outputTo);
 			rule.setActions(actions);
 			 			
 			// specify the length of the flow structure created
 			rule.setLength((short) (OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH)); 			
 				
 			logger.debug("install rule for destination {}", destMac);
 			
 			try {
 				sw.write(rule, null);
 			} catch (Exception e) {
 				e.printStackTrace();
 			}	
        
        // push the packet to the switch	
        	this.pushPacket(sw, match, pi, outPort);        	
        }       
        
        return Command.CONTINUE;
	}

	
	/*
	 * control logic which handles each packet in
	 */
	private Command ctrlLogicWithoutRules(IOFSwitch sw, OFPacketIn pi) {
		
        // Read in packet data headers by using OFMatch
        OFMatch match = new OFMatch();
        match.loadFromPacket(pi.getPacketData(), pi.getInPort());
		
		// take the source and destination mac from the packet
		Long sourceMac = Ethernet.toLong(match.getDataLayerSource());
        Long destMac   = Ethernet.toLong(match.getDataLayerDestination());
        
        Short inputPort = pi.getInPort();
        
        // if the (sourceMac, port) does not exist in MAC table
        //		add a new entry
        if (!macToPort.containsKey(sourceMac))
        	macToPort.put(sourceMac, inputPort);
        
        // if the destMac is in the MAC table take the outPort and send it there
        Short outPort = macToPort.get(destMac);
        this.pushPacket(sw, match, pi, 
       		(outPort == null) ? (short)OFPort.OFPP_FLOOD.getValue() : outPort);
        
        return Command.CONTINUE;
	}
	
	/*
	 * hub implementation
	 * */
	private Command ctrlLogicHub(IOFSwitch sw, OFPacketIn pi) {

        OFPacketOut po = (OFPacketOut) floodlightProvider.getOFMessageFactory()
                		.getMessage(OFType.PACKET_OUT);
        po.setBufferId(pi.getBufferId())
          .setInPort(pi.getInPort());

        // set actions
        OFActionOutput action = new OFActionOutput()
            .setPort((short) OFPort.OFPP_FLOOD.getValue());
        po.setActions(Collections.singletonList((OFAction)action));
        po.setActionsLength((short) OFActionOutput.MINIMUM_LENGTH);

        // set data if is is included in the packetin
        if (pi.getBufferId() == OFPacketOut.BUFFER_ID_NONE) {
            byte[] packetData = pi.getPacketData();
            po.setLength(U16.t(OFPacketOut.MINIMUM_LENGTH
                    + po.getActionsLength() + packetData.length));
            po.setPacketData(packetData);
        } else {
            po.setLength(U16.t(OFPacketOut.MINIMUM_LENGTH
                    + po.getActionsLength()));
        }
        try {
            sw.write(po, null);
        } catch (IOException e) {
            logger.error("Failure writing PacketOut", e);
        }
		
		return Command.CONTINUE;
	}
	
	
	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
				
        OFMatch match = new OFMatch();
        match.loadFromPacket(((OFPacketIn)msg).getPacketData(), 
        					 ((OFPacketIn)msg).getInPort());
        
 //       Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		
		if (match.getDataLayerType() != Ethernet.TYPE_IPv4)
			return Command.CONTINUE;
		
		switch (msg.getType()) {
		
			case PACKET_IN:
				logger.debug("Receive a packet !");
				
				if (LearningSwitch.CTRL_LEVEL == 1)
					return this.ctrlLogicHub(sw, (OFPacketIn) msg);
				else if (LearningSwitch.CTRL_LEVEL == 2)
					return this.ctrlLogicWithoutRules(sw, (OFPacketIn) msg);					
				else if (LearningSwitch.CTRL_LEVEL == 3)
					return this.ctrlLogicWithRules(sw, (OFPacketIn) msg);
				else if (LearningSwitch.CTRL_LEVEL == 4)
					return this.ctrlLogicWithFirewall(sw, (OFPacketIn) msg);
				else if (LearningSwitch.CTRL_LEVEL == 5)
					return this.ctrlLogicWithNAT(sw, (OFPacketIn)msg);
			default:
				break;
       }
       logger.error("received an unexpected message {} from switch {}", msg, sw);
       return Command.CONTINUE;
   }

	@Override
	public void addedSwitch(IOFSwitch sw) {
		//INSTALL STATIC RULES HERE
        // Insert drop UDP rule
      //  if (match.getNetworkProtocol() == IPv4.PROTOCOL_UDP) {
        	this.setFirewallRuleUDP(sw);
      //      return Command.CONTINUE;
      //  }
        
        // Insert drop TELNET rule
      //  if (match.getNetworkProtocol() == IPv4.PROTOCOL_TCP
      //  		&& match.getTransportDestination() == 23) {
        	this.setFirewallRuleTelnet(sw);
      //      return Command.CONTINUE;
      // }
        	
        	this.remapPortsStaticRule(sw);
        
	}

	@Override
	public void removedSwitch(IOFSwitch sw) {
		// TODO Auto-generated method stub
	}

	@Override
	public void switchPortChanged(Long switchId) {
		// TODO Auto-generated method stub
	}

}
