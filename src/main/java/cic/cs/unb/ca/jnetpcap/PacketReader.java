package cic.cs.unb.ca.jnetpcap;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapClosedException;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JHeaderPool;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import  org.jnetpcap.protocol.sigtran.Sctp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.vpn.L2TP;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


// Layer and PDU terminology 
// PDU (Protocol Data Unit): the data unit at a given network layer, including
// that layer's header plus everything it encapsulates
// 		L3 PDU = packet = IP datagram = L3 (IP) header + L4 header + L4 payload
// 		L4 PDU = segment = L4 unit = L4 (TCP/UDP/SCTP) header + L4 payload
// "segment" is used loosely throughout to mean any L4 PDU regardless of protocol
// strictly speaking, the correct terms should be: TCP segment, UDP datagram, etc.


public class PacketReader {

	private static final Logger logger = LoggerFactory.getLogger(PacketReader.class);
	private IdGenerator  generator = new IdGenerator();
	private Pcap pcapReader;
	
	private long firstPacket;
	private long lastPacket;
	
	private Tcp  tcp;
	private Udp  udp;
	private Icmp icmp;
	private Sctp sctp;
	private Ip4  ipv4;
	private Ip6  ipv6;
	private L2TP l2tp;
	private PcapHeader hdr;
	private JBuffer buf;
	
	private boolean readIP6;
	private boolean readIP4;
	private String file;
	
	public PacketReader(String filename) {
		super();	
		this.readIP4 = true;
		this.readIP6 = false;		
		this.config(filename);
	}
	
	public PacketReader(String filename, boolean readip4, boolean readip6) {
		super();	
		this.readIP4 = readip4;
		this.readIP6 = readip6;
		this.config(filename);
	}	
	
	private void config(String filename){
        file = filename;
		StringBuilder errbuf = new StringBuilder(); // For any error msgs
		pcapReader = Pcap.openOffline(filename, errbuf);
		
		this.firstPacket = 0L;
		this.lastPacket = 0L;

		if (pcapReader == null) {
			logger.error("Error while opening file for capture: "+errbuf.toString());
			System.exit(-1);
		}else{
			this.tcp = new Tcp();
			this.udp = new Udp();
			this.icmp = new Icmp();
			this.sctp = new Sctp();
			this.ipv4 = new Ip4();
			this.ipv6 = new Ip6();
			this.l2tp = new L2TP();
			hdr = new PcapHeader(JMemory.POINTER);
			buf = new JBuffer(JMemory.POINTER);		
		}		
	}

	public BasicPacketInfo nextPacket(){
		 PcapPacket      packet;
		 BasicPacketInfo packetInfo = null;
		 try{
			 if(pcapReader.nextEx(hdr,buf) == Pcap.NEXT_EX_OK){
				 packet = new PcapPacket(hdr, buf);
				 packet.scan(Ethernet.ID);				 
				 
				 if(this.readIP4){					 
					 packetInfo = getIpv4Info(packet);
					 if (packetInfo == null && this.readIP6){
					 	packetInfo = getIpv6Info(packet);				 	
					 }					 
				 }else if(this.readIP6){
					 packetInfo = getIpv6Info(packet);
					 if (packetInfo == null && this.readIP4){
					 	packetInfo = getIpv4Info(packet);
					 }
				 }
				 
				 if (packetInfo == null){
					 packetInfo = getVPNInfo(packet);
				 }					 

			 }else{
				 throw new PcapClosedException();
			 }
		 }catch(PcapClosedException e){
			 logger.debug("Read All packets on {}",file);
			 throw e;
		 }catch(Exception ex){
			 logger.debug(ex.getMessage());
		 }
		 return packetInfo;
	}
	
	private BasicPacketInfo getIpv4Info(PcapPacket packet){
		BasicPacketInfo packetInfo = null;		
		try {
						
			if (packet.hasHeader(ipv4)){
				packetInfo = new BasicPacketInfo(this.generator);
				packetInfo.setSrc(this.ipv4.source());
				packetInfo.setDst(this.ipv4.destination());
				//packetInfo.setTimeStamp(packet.getCaptureHeader().timestampInMillis());
				packetInfo.setTimeStamp(packet.getCaptureHeader().timestampInMicros());
				
				if(this.firstPacket == 0L)
					this.firstPacket = packet.getCaptureHeader().timestampInMillis();
				this.lastPacket = packet.getCaptureHeader().timestampInMillis();

				// set L3 header length
				// getHeaderLength() from class JHeader is in the inherited methods list of class Ip4 in the javadoc of jnetpcap
				packetInfo.setPacketHeaderBytes(this.ipv4.getHeaderLength());

				// This check needs to be first because ICMP protocol may embed the contents of
				// the original packet (so it will have tcp/udp headers as well).
				if (packet.hasHeader(this.icmp)) {
					packetInfo.setProtocol(ProtocolEnum.ICMP);
					packetInfo.setSrcPort(0);
					packetInfo.setDstPort(0);
					packetInfo.setIcmpCode(icmp.code());
					packetInfo.setIcmpType(icmp.type());
				} else if(packet.hasHeader(this.tcp)){
					packetInfo.setTCPWindow(tcp.window());
					packetInfo.setSrcPort(tcp.source());
					packetInfo.setDstPort(tcp.destination());
					packetInfo.setProtocol(ProtocolEnum.TCP);
					packetInfo.setFlagFIN(tcp.flags_FIN());
					packetInfo.setFlagPSH(tcp.flags_PSH());
					packetInfo.setFlagURG(tcp.flags_URG());
					packetInfo.setFlagSYN(tcp.flags_SYN());
					packetInfo.setFlagACK(tcp.flags_ACK());
					packetInfo.setFlagECE(tcp.flags_ECE());
					packetInfo.setFlagCWR(tcp.flags_CWR());
					packetInfo.setFlagRST(tcp.flags_RST());
					packetInfo.setPayloadBytes(tcp.getPayloadLength());
					packetInfo.setHeaderBytes(tcp.getHeaderLength());

					TcpRetransmissionDTO tcpRetransmissionDTO = new TcpRetransmissionDTO(
							this.ipv4.source(), tcp.seq(), tcp.ack(), tcp.getPayloadLength(),
							tcp.window(), packet.getCaptureHeader().timestampInMicros());
					packetInfo.setTcpRetransmissionDTO(tcpRetransmissionDTO);

				}else if(packet.hasHeader(this.udp)){
					packetInfo.setSrcPort(udp.source());
					packetInfo.setDstPort(udp.destination());
					packetInfo.setPayloadBytes(udp.getPayloadLength());
					packetInfo.setHeaderBytes(udp.getHeaderLength());
					packetInfo.setProtocol(ProtocolEnum.UDP);
				}else if(packet.hasHeader(this.sctp)){
					packetInfo.setSrcPort(sctp.source());
					packetInfo.setDstPort(sctp.destination());
					packetInfo.setPayloadBytes(sctp.getPayloadLength());
					packetInfo.setHeaderBytes(sctp.getHeaderLength());
					packetInfo.setProtocol(ProtocolEnum.SCTP);
			}else {

					Ip4.Ip4Type ip4Type = this.ipv4.typeEnum();

					switch (ip4Type) {
						case IGMP:
							packetInfo.setProtocol(ProtocolEnum.IGMP);
							break;
						default:
							/** Note, we are not supporting all protocols, just the ones we are interested in, and adding
							    them as desired. To be considered at a future point, if we want to include a lot more protocols,
							    it may be a lot cleaner to just use the Ip4.Ip4Type enum directly.
							 */
							logger.debug("Currently unsupported Ip4 protocol: {} --description: {} ", ip4Type.name(), ip4Type.getDescription());
							break;
					}



					/*logger.debug("other packet Ethernet -> {}"+  packet.hasHeader(new Ethernet()));
					logger.debug("other packet Html     -> {}"+  packet.hasHeader(new Html()));
					logger.debug("other packet Http     -> {}"+  packet.hasHeader(new Http()));
					logger.debug("other packet SLL      -> {}"+  packet.hasHeader(new SLL()));
					logger.debug("other packet L2TP     -> {}"+  packet.hasHeader(new L2TP()));
					logger.debug("other packet PPP      -> {}"+  packet.hasHeader(new PPP()));*/

//					int headerCount = packet.getHeaderCount();
//					for(int i=0;i<headerCount;i++) {
//						JHeader header = JHeaderPool.getDefault().getHeader(i);
//						//JHeader hh = packet.getHeaderByIndex(i, header);
//						//logger.debug("getIpv4Info: {} --description: {} ",header.getName(),header.getDescription());
//					}
				}
			}
		} catch (Exception e) {
			//e.printStackTrace();
			packet.scan(ipv4.getId());
			String errormsg = "";
			errormsg+=e.getMessage()+"\n";
			//errormsg+=packet.getHeader(new Ip4())+"\n";
			errormsg+="********************************************************************************"+"\n";
			errormsg+=packet.toHexdump()+"\n";
			
			//System.out.println(errormsg);
			logger.debug(errormsg);
			//System.exit(-1);
			return null;
		}
		
		return packetInfo;
	}
	
	private BasicPacketInfo getIpv6Info(PcapPacket packet){
		BasicPacketInfo packetInfo = null;
		try{
			if(packet.hasHeader(ipv6)){
				packetInfo = new BasicPacketInfo(this.generator);
				packetInfo.setSrc(this.ipv6.source());
				packetInfo.setDst(this.ipv6.destination());
				packetInfo.setTimeStamp(packet.getCaptureHeader().timestampInMillis());			

				// set L3 header length
				// getHeaderLength() from class JHeader is in the inherited methods list of class Ip6 in the javadoc of jnetpcap
				packetInfo.setPacketHeaderBytes(this.ipv6.getHeaderLength());

				if(packet.hasHeader(this.tcp)){						
					packetInfo.setSrcPort(tcp.source());
					packetInfo.setDstPort(tcp.destination());
					packetInfo.setPayloadBytes(tcp.getPayloadLength());
					packetInfo.setHeaderBytes(tcp.getHeaderLength());
					packetInfo.setProtocol(ProtocolEnum.TCP);
				}else if(packet.hasHeader(this.udp)){
					packetInfo.setSrcPort(udp.source());
					packetInfo.setDstPort(udp.destination());
					packetInfo.setPayloadBytes(udp.getPayloadLength());
					packetInfo.setHeaderBytes(tcp.getHeaderLength());
					packetInfo.setProtocol(ProtocolEnum.UDP);
				}		
			}
		}catch(Exception e){
			logger.debug(e.getMessage());
			packet.scan(ipv6.getId());
			String errormsg = "";
			errormsg+=e.getMessage()+"\n";
			//errormsg+=packet.getHeader(new Ip6())+"\n";
			errormsg+="********************************************************************************"+"\n";
			errormsg+=packet.toHexdump()+"\n";
			
			//System.out.println(errormsg);
			logger.debug(errormsg);
			//System.exit(-1);
			return null;			
		}
				
		return packetInfo;
	}
	
	private BasicPacketInfo getVPNInfo(PcapPacket packet){		
		BasicPacketInfo packetInfo = null;		
		try {
			packet.scan(L2TP.ID);
			
			if (packet.hasHeader(l2tp)){				
		    	if(this.readIP4){		
		    		packet.scan(ipv4.getId());
		    		packetInfo = getIpv4Info(packet);
		    		if (packetInfo == null && this.readIP6){
		    			packet.scan(ipv6.getId());
		    			packetInfo = getIpv6Info(packet);				 	
		    		}					 
		    	}else if(this.readIP6){
		    		packet.scan(ipv6.getId());
		    		packetInfo = getIpv6Info(packet);
		    		if (packetInfo == null && this.readIP4){
		    			packet.scan(ipv4.getId());
		    			packetInfo = getIpv4Info(packet);
		    		}
		    	}				

			}
		} catch (Exception e) {
			logger.debug(e.getMessage());
			packet.scan(l2tp.getId());
			String errormsg = "";
			errormsg+=e.getMessage()+"\n";
			//errormsg+=packet.getHeader(new L2TP())+"\n";
			errormsg+="********************************************************************************"+"\n";
			errormsg+=packet.toHexdump()+"\n";
			
			//System.out.println(errormsg);
			logger.debug(errormsg);
			//System.exit(-1);
			return null;
		}
		
		return packetInfo;
	}	

	public long getFirstPacket() {
		return firstPacket;
	}

	public void setFirstPacket(long firstPacket) {
		this.firstPacket = firstPacket;
	}

	public long getLastPacket() {
		return lastPacket;
	}

	public void setLastPacket(long lastPacket) {
		this.lastPacket = lastPacket;
	}	

	/*
	 * So far,The value of the field BasicPacketInfo.id is not used
	 * It doesn't matter just using a static IdGenerator for realtime PcapPacket reading
	 */
	private static IdGenerator idGen = new IdGenerator();
	public static BasicPacketInfo getBasicPacketInfo(PcapPacket packet,boolean readIP4, boolean readIP6) {
		BasicPacketInfo packetInfo = null;
		
		
		Protocol protocol = new Protocol();
		
		if(readIP4){					 
			packetInfo = getIpv4Info(packet,protocol);
			if (packetInfo == null && readIP6){
				packetInfo = getIpv6Info(packet,protocol);				 	
			}					 
		}else if(readIP6){
			packetInfo = getIpv6Info(packet,protocol);
			if (packetInfo == null && readIP4){
				packetInfo = getIpv4Info(packet,protocol);
			}
		}
		
		if (packetInfo == null){
			packetInfo = getVPNInfo(packet,protocol,readIP4,readIP6);
		}
		
		return packetInfo;
	}

	private static BasicPacketInfo getVPNInfo(PcapPacket packet,Protocol protocol,boolean readIP4, boolean readIP6) {		
		BasicPacketInfo packetInfo = null;
		try {
			packet.scan(L2TP.ID);
			
			if (packet.hasHeader(protocol.getL2tp())){
		    	if(readIP4){		
		    		packet.scan(protocol.getIpv4().getId());
		    		packetInfo = getIpv4Info(packet,protocol);
		    		if (packetInfo == null && readIP6){
		    			packet.scan(protocol.getIpv6().getId());
		    			packetInfo = getIpv6Info(packet,protocol);				 	
		    		}					 
		    	}else if(readIP6){
		    		packet.scan(protocol.getIpv6().getId());
		    		packetInfo = getIpv6Info(packet,protocol);
		    		if (packetInfo == null && readIP4){
		    			packet.scan(protocol.getIpv4().getId());
		    			packetInfo = getIpv4Info(packet,protocol);
		    		}
		    	}				

			}
		} catch (Exception e) {
			/*
			 * BufferUnderflowException while decoding header
			 * havn't fixed, so do not e.printStackTrace() 
			 */
			//e.printStackTrace();
			/*packet.scan(protocol.l2tp.getId());
			String errormsg = "";
			errormsg+=e.getMessage()+"\n";
			//errormsg+=packet.getHeader(new L2TP())+"\n";
			errormsg+="********************************************************************************"+"\n";
			errormsg+=packet.toHexdump()+"\n";
			logger.error(errormsg);*/
			return null;
		}
		
		return packetInfo;
	}

	private static BasicPacketInfo getIpv6Info(PcapPacket packet,Protocol protocol) {
		BasicPacketInfo packetInfo = null;
		try{
			if(packet.hasHeader(protocol.getIpv6())){
				packetInfo = new BasicPacketInfo(idGen);
				packetInfo.setSrc(protocol.getIpv6().source());
				packetInfo.setDst(protocol.getIpv6().destination());
				packetInfo.setTimeStamp(packet.getCaptureHeader().timestampInMillis());			
				
				// set L3 header length
				packetInfo.setPacketHeaderBytes(protocol.getIpv6().getHeaderLength());

				if(packet.hasHeader(protocol.getTcp())){
					packetInfo.setSrcPort(protocol.getTcp().source());
					packetInfo.setDstPort(protocol.getTcp().destination());
					packetInfo.setPayloadBytes(protocol.getTcp().getPayloadLength());
					packetInfo.setHeaderBytes(protocol.getTcp().getHeaderLength());
					packetInfo.setProtocol(ProtocolEnum.TCP);
				}else if(packet.hasHeader(protocol.getUdp())){
					packetInfo.setSrcPort(protocol.getUdp().source());
					packetInfo.setDstPort(protocol.getUdp().destination());
					packetInfo.setPayloadBytes(protocol.getUdp().getPayloadLength());
					packetInfo.setHeaderBytes(protocol.getUdp().getHeaderLength());
					packetInfo.setProtocol(ProtocolEnum.UDP);
				}		
			}
		}catch(Exception e){
			/*
			 * BufferUnderflowException while decoding header
			 * havn't fixed, so do not e.printStackTrace()
			 */
			//e.printStackTrace();
			/*packet.scan(protocol.ipv6.getId());
			String errormsg = "";
			errormsg+=e.getMessage()+"\n";
			//errormsg+=packet.getHeader(new Ip6())+"\n";
			errormsg+="********************************************************************************"+"\n";
			errormsg+=packet.toHexdump()+"\n";
			logger.error(errormsg);
			//System.exit(-1);*/
			return null;			
		}
				
		return packetInfo;
	}

	private static BasicPacketInfo getIpv4Info(PcapPacket packet,Protocol protocol) {
		BasicPacketInfo packetInfo = null;		
		try {
						
			if (packet.hasHeader(protocol.getIpv4())){
				packetInfo = new BasicPacketInfo(idGen);
				packetInfo.setSrc(protocol.getIpv4().source());
				packetInfo.setDst(protocol.getIpv4().destination());
				//packetInfo.setTimeStamp(packet.getCaptureHeader().timestampInMillis());
				packetInfo.setTimeStamp(packet.getCaptureHeader().timestampInMicros());
				
				/*if(this.firstPacket == 0L)
					this.firstPacket = packet.getCaptureHeader().timestampInMillis();
				this.lastPacket = packet.getCaptureHeader().timestampInMillis();*/

				// set L3 header length
				packetInfo.setPacketHeaderBytes(protocol.getIpv4().getHeaderLength());

				if(packet.hasHeader(protocol.getTcp())){
					packetInfo.setTCPWindow(protocol.getTcp().window());
					packetInfo.setSrcPort(protocol.getTcp().source());
					packetInfo.setDstPort(protocol.getTcp().destination());
					packetInfo.setProtocol(ProtocolEnum.TCP);
					packetInfo.setFlagFIN(protocol.getTcp().flags_FIN());
					packetInfo.setFlagPSH(protocol.getTcp().flags_PSH());
					packetInfo.setFlagURG(protocol.getTcp().flags_URG());
					packetInfo.setFlagSYN(protocol.getTcp().flags_SYN());
					packetInfo.setFlagACK(protocol.getTcp().flags_ACK());
					packetInfo.setFlagECE(protocol.getTcp().flags_ECE());
					packetInfo.setFlagCWR(protocol.getTcp().flags_CWR());
					packetInfo.setFlagRST(protocol.getTcp().flags_RST());
					packetInfo.setPayloadBytes(protocol.getTcp().getPayloadLength());
					packetInfo.setHeaderBytes(protocol.getTcp().getHeaderLength());
				}else if(packet.hasHeader(protocol.getUdp())){
					packetInfo.setSrcPort(protocol.getUdp().source());
					packetInfo.setDstPort(protocol.getUdp().destination());
					packetInfo.setPayloadBytes(protocol.getUdp().getPayloadLength());
					packetInfo.setHeaderBytes(protocol.getUdp().getHeaderLength());
					packetInfo.setProtocol(ProtocolEnum.UDP);
				} else {
					int headerCount = packet.getHeaderCount();
					for(int i=0;i<headerCount;i++) {
						JHeader header = JHeaderPool.getDefault().getHeader(i);
						//JHeader hh = packet.getHeaderByIndex(i, header);
						//logger.debug("getIpv4Info: {} --description: {} ",header.getName(),header.getDescription());
					}
				}
			}
		} catch (Exception e) {
			/*
			 * BufferUnderflowException while decoding header
			 * havn't fixed, so do not e.printStackTrace()
			 */
			//e.printStackTrace();
			/*packet.scan(protocol.ipv4.getId());
			String errormsg = "";
			errormsg+=e.getMessage()+"\n";
			//errormsg+=packet.getHeader(new Ip4())+"\n";
			errormsg+="********************************************************************************"+"\n";
			errormsg+=packet.toHexdump()+"\n";
			logger.error(errormsg);
			return null;*/
		}
		
		return packetInfo;
	}
}
