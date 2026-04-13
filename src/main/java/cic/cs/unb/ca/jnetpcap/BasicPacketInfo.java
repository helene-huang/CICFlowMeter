package cic.cs.unb.ca.jnetpcap;

import java.util.Arrays;

import org.jnetpcap.packet.format.FormatUtils;


// Layer and PDU terminology 
// PDU (Protocol Data Unit): the data unit at a given network layer, including
// that layer's header plus everything it encapsulates
// 		L3 PDU = packet = IP datagram = L3 (IP) header + L4 header + L4 payload
// 		L4 PDU = segment = L4 unit = L4 (TCP/UDP/SCTP) header + L4 payload
// "segment" is used loosely throughout to mean any L4 PDU regardless of protocol
// strictly speaking, the correct terms should be: TCP segment, UDP datagram, etc.



public class BasicPacketInfo {
	
/*  Basic Info to generate flows from packets  	*/
    private    long id;
    private    byte[] src;
    private    byte[] dst;
    private    int srcPort;
    private    int dstPort;
    private    ProtocolEnum protocol = ProtocolEnum.DEFAULT;
    private    long   timeStamp;
    private    long   payloadBytes;  // L4 payload length = segment payload length, in bytes
    private    String  flowId = null;  
/* ******************************************** */    
    private    boolean flagFIN = false;
	private    boolean flagPSH = false;
	private    boolean flagURG = false;
	private    boolean flagECE = false;
	private    boolean flagSYN = false;
	private    boolean flagACK = false;
	private    boolean flagCWR = false;
	private    boolean flagRST = false;
	private	   int TCPWindow=0;
	private	   long headerBytes;  // L4 header length = segment header length, in bytes 
	private long packetHeaderBytes; // L3 header length = packet header length, in bytes
	private int payloadPacket=0;
	/* ** ICMP FIELDS ** */
	private int icmpCode = -1;
	private int icmpType = -1;

	private TcpRetransmissionDTO tcpRetransmissionDTO;

	public BasicPacketInfo(byte[] src, byte[] dst, int srcPort, int dstPort,
			ProtocolEnum protocol, long timeStamp, IdGenerator generator) {
		super();
		this.id = generator.nextId();
		this.src = src;
		this.dst = dst;
		this.srcPort = srcPort;
		this.dstPort = dstPort;
		this.protocol = protocol;
		this.timeStamp = timeStamp;
		generateFlowId();
	}
	
    public BasicPacketInfo(IdGenerator generator) {
		super();
		this.id = generator.nextId();
	}
    
    

	public String generateFlowId(){
    	boolean forward = true;
    	
    	for(int i=0; i<this.src.length;i++){           
    		if(((Byte)(this.src[i])).intValue() != ((Byte)(this.dst[i])).intValue()){
    			if(((Byte)(this.src[i])).intValue() >((Byte)(this.dst[i])).intValue()){
    				forward = false;
    			}
    			i=this.src.length;
    		}
    	}     	
    	
        if(forward){
            this.flowId = this.getSourceIP() + "-" + this.getDestinationIP() + "-" + this.srcPort  + "-" + this.dstPort  + "-" + this.protocol.val;
        }else{
            this.flowId = this.getDestinationIP() + "-" + this.getSourceIP() + "-" + this.dstPort  + "-" + this.srcPort  + "-" + this.protocol.val;
        }
        return this.flowId;
	}

 	public String fwdFlowId() {  
		this.flowId = this.getSourceIP() + "-" + this.getDestinationIP() + "-" + this.srcPort  + "-" + this.dstPort  + "-" + this.protocol.val;
		return this.flowId;
	}
	
	public String bwdFlowId() {  
		this.flowId = this.getDestinationIP() + "-" + this.getSourceIP() + "-" + this.dstPort  + "-" + this.srcPort  + "-" + this.protocol.val;
		return this.flowId;
	}


    
	public String dumpInfo() {
		return null;
	}
	public int getPayloadPacket() {
		return payloadPacket+=1;
	}
          
    
    public String getSourceIP(){
    	return FormatUtils.ip(this.src);
    }

    public String getDestinationIP(){
    	return FormatUtils.ip(this.dst);
    }
    
    
	public long getId() {
		return id;
	}

	public void setId(long id) {
		this.id = id;
	}

	public byte[] getSrc() {
		return Arrays.copyOf(src,src.length);
	}

	public void setSrc(byte[] src) {
		this.src = src;
	}

	public byte[] getDst() {
		return Arrays.copyOf(dst,dst.length);
	}

	public void setDst(byte[] dst) {
		this.dst = dst;
	}

	public int getSrcPort() {
		return srcPort;
	}

	public void setSrcPort(int srcPort) {
		this.srcPort = srcPort;
	}

	public int getDstPort() {
		return dstPort;
	}

	public void setDstPort(int dstPort) {
		this.dstPort = dstPort;
	}

	public ProtocolEnum getProtocol() {
		return protocol;
	}

	public void setProtocol(ProtocolEnum protocol) {
		this.protocol = protocol;
	}

	public long getTimeStamp() {
		return timeStamp;
	}

	public void setTimeStamp(long timeStamp) {
		this.timeStamp = timeStamp;
	}

	public String getFlowId() {
		return this.flowId!=null?this.flowId:generateFlowId();
	}

	public void setFlowId(String flowId) {		
		this.flowId = flowId;
	}

	public boolean isForwardPacket(byte[] sourceIP) {
		return Arrays.equals(sourceIP, this.src);
	}

	// L4 payload length getter
	public long getPayloadBytes() {
		return payloadBytes;
	}

	// L4 payload length setter
	public void setPayloadBytes(long payloadBytes) {
		this.payloadBytes = payloadBytes;
	}

	// L4 header length getter
	public long getHeaderBytes() {
		return headerBytes;
	}

	// L4 header length setter
	public void setHeaderBytes(long headerBytes) {
		this.headerBytes = headerBytes;
	}

	// L3 header length getter
	public long getPacketHeaderBytes() {
		return packetHeaderBytes;
	}	

	// L3 header length setter
	public void setPacketHeaderBytes(long packetHeaderBytes) {
		this.packetHeaderBytes = packetHeaderBytes;
	}

	public boolean hasFlagFIN() {
		return flagFIN;
	}

	public void setFlagFIN(boolean flagFIN) {
		this.flagFIN = flagFIN;
	}

	public boolean hasFlagPSH() {
		return flagPSH;
	}

	public void setFlagPSH(boolean flagPSH) {
		this.flagPSH = flagPSH;
	}

	public boolean hasFlagURG() {
		return flagURG;
	}

	public void setFlagURG(boolean flagURG) {
		this.flagURG = flagURG;
	}

	public boolean hasFlagECE() {
		return flagECE;
	}

	public void setFlagECE(boolean flagECE) {
		this.flagECE = flagECE;
	}

	public boolean hasFlagSYN() {
		return flagSYN;
	}

	public void setFlagSYN(boolean flagSYN) {
		this.flagSYN = flagSYN;
	}

	public boolean hasFlagACK() {
		return flagACK;
	}

	public void setFlagACK(boolean flagACK) {
		this.flagACK = flagACK;
	}

	public boolean hasFlagCWR() {
		return flagCWR;
	}

	public void setFlagCWR(boolean flagCWR) {
		this.flagCWR = flagCWR;
	}

	public boolean hasFlagRST() {
		return flagRST;
	}

	public void setFlagRST(boolean flagRST) {
		this.flagRST = flagRST;
	}

	public int getTCPWindow(){
		return TCPWindow;
	}

	public void setTCPWindow(int TCPWindow){
		this.TCPWindow = TCPWindow;
	}

	public int getIcmpCode() {
		return this.icmpCode;
	}

	public void setIcmpCode(int icmpCode) {
		this.icmpCode = icmpCode;
	}

	public int getIcmpType() {
		return this.icmpType;
	}

	public void setIcmpType(int icmpType) {
		this.icmpType = icmpType;
	}

	public TcpRetransmissionDTO tcpRetransmissionDTO(){
		return this.tcpRetransmissionDTO;
	}

	public void setTcpRetransmissionDTO(TcpRetransmissionDTO tcpRetransmissionDTO) {
		this.tcpRetransmissionDTO = tcpRetransmissionDTO;
	}
}
