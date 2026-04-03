package cic.cs.unb.ca.jnetpcap;

import java.util.*;

import org.apache.commons.math3.stat.descriptive.SummaryStatistics;
import org.jnetpcap.packet.format.FormatUtils;

public class BasicFlow {

    private final static String separator = ",";
    private SummaryStatistics fwdPktStats = null;
    private SummaryStatistics bwdPktStats = null;
    private List<BasicPacketInfo> forward = null;
    private List<BasicPacketInfo> backward = null;

    private long forwardBytes;
    private long backwardBytes;
    private long fHeaderBytes;
    private long bHeaderBytes;

    // Is always the value true in this application
    private boolean isBidirectional;

    // two hashmaps tracking all 8 TCP flags (CWR, ECE, URG, ACK, PSH, RST, SYN, FIN) separately for each direction
    // totals counts are going to be derived by summing fwd and bwd counts, so we don't need a third combined map to store total counts
    private HashMap<String, MutableInt> fwdFlagCounts;  // flags seen in fwd packets
    private HashMap<String, MutableInt> bwdFlagCounts;  // flags seen in bwd packets

    private long Act_data_pkt_forward;
    private long Act_data_pkt_backward;
    private long min_seg_size_forward;
    private long min_seg_size_backward;
    private int Init_Win_bytes_forward = 0;
    private int Init_Win_bytes_backward = 0;


    private byte[] src;
    private byte[] dst;
    private int srcPort;
    private int dstPort;
    private ProtocolEnum protocol;
    private long flowStartTime;
    private long startActiveTime;
    private long endActiveTime;
    private String flowId = null;

    private SummaryStatistics flowIAT = null;
    private SummaryStatistics forwardIAT = null;
    private SummaryStatistics backwardIAT = null;
    private SummaryStatistics flowLengthStats = null;
    private SummaryStatistics flowActive = null;
    private SummaryStatistics flowIdle = null;

    private long flowLastSeen;
    private long forwardLastSeen;
    private long backwardLastSeen;
    private long activityTimeout;
    private long sfLastPacketTS = -1;
    private int sfCount = 0;
    private long sfAcHelper = -1;
    //////////////////////////////
    private long fbulkDuration = 0;
    private long fbulkPacketCount = 0;
    private long fbulkSizeTotal = 0;
    private long fbulkStateCount = 0;
    private long fbulkPacketCountHelper = 0;
    private long fbulkStartHelper = 0;
    private long fbulkSizeHelper = 0;
    private long flastBulkTS = 0;
    private long bbulkDuration = 0;
    private long bbulkPacketCount = 0;
    private long bbulkSizeTotal = 0;
    private long bbulkStateCount = 0;
    private long bbulkPacketCountHelper = 0;
    private long bbulkStartHelper = 0;
    private long bbulkSizeHelper = 0;
    private long blastBulkTS = 0;

    private int fwdTcpRetransCnt = 0;
    private int bwdTcpRetransCnt = 0;
    private Set<TcpRetransmissionDTO> tcpPacketsSeen;

    // The flow timeout is dependent on the user configuration and is unable to capture proper
    // context in extended TCP connections. This field will help identify whether a flow is
    // part of an extended TCP connection.
    private long cumulativeConnectionDuration;

    //To keep track of TCP connection teardown, or an RST packet in one direction.
    private TcpFlowState tcpFlowState;

    // ICMP fields
    private int icmpCode = -1;
    private int icmpType = -1;

    public BasicFlow(boolean isBidirectional, BasicPacketInfo packet, byte[] flowSrc, byte[] flowDst, int flowSrcPort,
                     int flowDstPort, long activityTimeout) {
        super();
        this.activityTimeout = activityTimeout;
        this.initParameters();
        this.isBidirectional = isBidirectional;
        this.src = flowSrc;
        this.dst = flowDst;
        this.srcPort = flowSrcPort;
        this.dstPort = flowDstPort;
        this.firstPacket(packet);
    }

    public BasicFlow(boolean isBidirectional, BasicPacketInfo packet, byte[] flowSrc, byte[] flowDst, int flowSrcPort,
            int flowDstPort, long activityTimeout, Set<TcpRetransmissionDTO> tcpPacketsSeen) {
        super();
        this.activityTimeout = activityTimeout;
        this.initParameters();
        this.isBidirectional = isBidirectional;
        this.src = flowSrc;
        this.dst = flowDst;
        this.srcPort = flowSrcPort;
        this.dstPort = flowDstPort;
        this.tcpPacketsSeen = tcpPacketsSeen;
        this.firstPacket(packet);
    }


    public BasicFlow(boolean isBidirectional, BasicPacketInfo packet, long activityTimeout) {
        super();
        this.activityTimeout = activityTimeout;
        this.initParameters();
        this.isBidirectional = isBidirectional;
        this.firstPacket(packet);
    }

    public BasicFlow(BasicPacketInfo packet, long activityTimeout) {
        super();
        this.activityTimeout = activityTimeout;
        this.initParameters();
        this.isBidirectional = true;
        firstPacket(packet);
    }


    public void initParameters() {
        this.forward = new ArrayList<BasicPacketInfo>();
        this.backward = new ArrayList<BasicPacketInfo>();
        this.flowIAT = new SummaryStatistics();
        this.forwardIAT = new SummaryStatistics();
        this.backwardIAT = new SummaryStatistics();
        this.flowActive = new SummaryStatistics();
        this.flowIdle = new SummaryStatistics();
        this.flowLengthStats = new SummaryStatistics();
        this.fwdPktStats = new SummaryStatistics();
        this.bwdPktStats = new SummaryStatistics();
        initFlags();  // redefined in a way that initialises the fwd and bwd hashmaps that track the fwd and bwd flags separately
        this.forwardBytes = 0L;
        this.backwardBytes = 0L;
        this.startActiveTime = 0L;
        this.endActiveTime = 0L;
        this.src = null;
        this.dst = null;
        this.fHeaderBytes = 0L;
        this.bHeaderBytes = 0L;
        this.cumulativeConnectionDuration = 0L;
        this.tcpFlowState = null;
        this.tcpPacketsSeen = new HashSet<TcpRetransmissionDTO>();
    }

    public void firstPacket(BasicPacketInfo packet) {
        
        if (this.src == null) {
            this.src = packet.getSrc();
            this.srcPort = packet.getSrcPort();
        }
        if (this.dst == null) {
            this.dst = packet.getDst();
            this.dstPort = packet.getDstPort();
        }

        updateFlowBulk(packet);

        checkFlags(packet);

        this.endActiveTime = packet.getTimeStamp();
        this.flowStartTime = packet.getTimeStamp();
        this.flowLastSeen = packet.getTimeStamp();
        this.startActiveTime = packet.getTimeStamp();
        detectUpdateSubflows(packet);
        this.flowLengthStats.addValue((double) packet.getPayloadBytes());

        if (Arrays.equals(this.src, packet.getSrc())) {
            this.min_seg_size_forward = packet.getHeaderBytes();
            Init_Win_bytes_forward = packet.getTCPWindow();
            this.fwdPktStats.addValue((double) packet.getPayloadBytes());
            this.fHeaderBytes = packet.getHeaderBytes();
            this.forwardLastSeen = packet.getTimeStamp();
            this.forwardBytes += packet.getPayloadBytes();
            this.forward.add(packet);
            if (packet.getPayloadBytes() >= 1) {
                this.Act_data_pkt_forward++;
            }
        } else {
            this.min_seg_size_backward = packet.getHeaderBytes();
            Init_Win_bytes_backward = packet.getTCPWindow();
            this.bwdPktStats.addValue((double) packet.getPayloadBytes());
            this.bHeaderBytes = packet.getHeaderBytes();
            this.backwardLastSeen = packet.getTimeStamp();
            this.backwardBytes += packet.getPayloadBytes();
            this.backward.add(packet);
            if (packet.getPayloadBytes() >= 1) {
                this.Act_data_pkt_backward++;
            }
        }
        this.protocol = packet.getProtocol();
        this.icmpCode = packet.getIcmpCode();
        this.icmpType = packet.getIcmpType();
        this.flowId = packet.getFlowId();
        handleTcpRetransmissionFields(packet);
    }

    /***
     * The retransmission mechanism is crude, and relies on the fact that the fields in the TcpRetransmissionDTO
     * class are unique. This is not a perfect solution, but it should be good enough for detection of very obvious
     * TCP retransmissions.
     * @param packet
     */
    private void handleTcpRetransmissionFields(BasicPacketInfo packet) {
        if (this.protocol == ProtocolEnum.TCP) {
            TcpRetransmissionDTO tcpRetransmissionDTO = packet.tcpRetransmissionDTO();
            // If the element was successfully added to the hashset, then it has not been seen
            // before, and is not a retransmission.
            boolean isRetransmission = !(this.tcpPacketsSeen.add(tcpRetransmissionDTO));
            if (isRetransmission) {
                // check if the packet is a forward packet
                if (Arrays.equals(this.src, packet.getSrc())) {
                    // increment the forward retransmission count
                    this.fwdTcpRetransCnt++;
                } else {
                    // increment the backward retransmission count
                    this.bwdTcpRetransCnt++;
                }
            }
        }
    }

    public void addPacket(BasicPacketInfo packet) {
        updateFlowBulk(packet);
        detectUpdateSubflows(packet);
        checkFlags(packet);
        handleTcpRetransmissionFields(packet);
        long currentTimestamp = packet.getTimeStamp();
        if (isBidirectional) {
            this.flowLengthStats.addValue((double) packet.getPayloadBytes());
            if (Arrays.equals(this.src, packet.getSrc())) {
                if (packet.getPayloadBytes() >= 1) {
                    this.Act_data_pkt_forward++;
                }
                this.fwdPktStats.addValue((double) packet.getPayloadBytes());
                this.fHeaderBytes += packet.getHeaderBytes();
                this.forward.add(packet);
                this.forwardBytes += packet.getPayloadBytes();
                if (this.forward.size() > 1)
                    this.forwardIAT.addValue(currentTimestamp - this.forwardLastSeen);
                this.forwardLastSeen = currentTimestamp;
                this.min_seg_size_forward = Math.min(packet.getHeaderBytes(), this.min_seg_size_forward);
            } else {
                if (packet.getPayloadBytes() >= 1) {
                    this.Act_data_pkt_backward++;
                }
                this.bwdPktStats.addValue((double) packet.getPayloadBytes());
                // set Init_win_bytes_backward if not been set. The set logic isn't 100%
                // accurate, since it technically takes the first non-zero value, but should
                // be good enough for most cases.
                if (Init_Win_bytes_backward == 0) {
                    Init_Win_bytes_backward = packet.getTCPWindow();
                }
                this.bHeaderBytes += packet.getHeaderBytes();
                this.backward.add(packet);
                this.backwardBytes += packet.getPayloadBytes();
                if (this.backward.size() > 1)
                    this.backwardIAT.addValue(currentTimestamp - this.backwardLastSeen);
                this.backwardLastSeen = currentTimestamp;
                this.min_seg_size_backward = Math.min(packet.getHeaderBytes(), this.min_seg_size_backward);
            }
        } else {
            if (packet.getPayloadBytes() >= 1) {
                this.Act_data_pkt_forward++;
            }
            this.fwdPktStats.addValue((double) packet.getPayloadBytes());
            this.flowLengthStats.addValue((double) packet.getPayloadBytes());
            this.fHeaderBytes += packet.getHeaderBytes();
            this.forward.add(packet);
            this.forwardBytes += packet.getPayloadBytes();
            this.forwardIAT.addValue(currentTimestamp - this.forwardLastSeen);
            this.forwardLastSeen = currentTimestamp;
            this.min_seg_size_forward = Math.min(packet.getHeaderBytes(), this.min_seg_size_forward);
        }

        this.flowIAT.addValue(packet.getTimeStamp() - this.flowLastSeen);
        this.flowLastSeen = packet.getTimeStamp();

    }

    public double getfPktsPerSecond() {
        long duration = this.flowLastSeen - this.flowStartTime;
        if (duration > 0) {
            return (this.forward.size() / ((double) duration / 1000000L));
        } else
            return 0;
    }

    public double getbPktsPerSecond() {
        long duration = this.flowLastSeen - this.flowStartTime;
        if (duration > 0) {
            return (this.backward.size() / ((double) duration / 1000000L));
        } else
            return 0;
    }

    public double getDownUpRatio() {
        if (this.forward.size() > 0) {
            return ((double)this.backward.size())/this.forward.size();
        }
        return 0;
    }

    public double getAvgPacketSize() {
        if (this.packetCount() > 0) {
            return (this.flowLengthStats.getSum() / this.packetCount());
        }
        return 0;
    }

    public double fAvgSegmentSize() {
        if (this.forward.size() != 0)
            return (this.fwdPktStats.getSum() / (double) this.forward.size());
        return 0;
    }

    public double bAvgSegmentSize() {
        if (this.backward.size() != 0)
            return (this.bwdPktStats.getSum() / (double) this.backward.size());
        return 0;
    }

    // helper method that creates one fresh flag hashmap with all 8 flags set to zero
    // called twice by initFlags(): once to create the fwd flag hashmap, once to create the bwd flag hashmap
    private HashMap<String, MutableInt> createFlagMap() {
        HashMap<String, MutableInt> map = new HashMap<>();
        map.put("FIN", new MutableInt());  // add key "FIN" and say that the value is a MutableInt
        map.put("SYN", new MutableInt());
        map.put("RST", new MutableInt());
        map.put("PSH", new MutableInt());
        map.put("ACK", new MutableInt());
        map.put("URG", new MutableInt());
        map.put("CWR", new MutableInt());
        map.put("ECE", new MutableInt());
        return map;  // return the completed map
    }

    // initialises both directional flag maps to all-zero counts
    // called from initParameters() at the start of every new flow
    public void initFlags() {
        this.fwdFlagCounts = createFlagMap();  // fwd direction: all flags start at 0
        this.bwdFlagCounts = createFlagMap();  // bwd direction: all flags start at 0
    }

    // called for every packet (both in firstPacket() and addPacket())
    // the idea is to first figure out if it's a fwd or bwd packet, then increment
    // the right flag counter in the right directional map
    public void checkFlags(BasicPacketInfo packet) {
        // Arrays.equals() compares byte arrays by content (like python's == for lists to check if all elements of an ordered list are the same)
        // if packet src IP is the same as the flow src IP then it's a fwd packet, and if not, it's a bwd packet
        HashMap<String, MutableInt> dirMap;  // directional hashmap
        if (Arrays.equals(this.src, packet.getSrc())) {
            dirMap = fwdFlagCounts;
        } else {
            dirMap = bwdFlagCounts;
        }

        // now increment whichever flags this packet has set
        if (packet.hasFlagFIN()) dirMap.get("FIN").increment();
        if (packet.hasFlagSYN()) dirMap.get("SYN").increment();
        if (packet.hasFlagRST()) dirMap.get("RST").increment();
        if (packet.hasFlagPSH()) dirMap.get("PSH").increment();
        if (packet.hasFlagACK()) dirMap.get("ACK").increment();
        if (packet.hasFlagURG()) dirMap.get("URG").increment();
        if (packet.hasFlagCWR()) dirMap.get("CWR").increment();
        if (packet.hasFlagECE()) dirMap.get("ECE").increment();
    }

    public double getSflow_fbytes() {
        if (sfCount <= 0) return 0;
        return (double) this.forwardBytes / sfCount;
    }

    public double getSflow_fpackets() {
        if (sfCount <= 0) return 0;
        return (double) this.forward.size() / sfCount;
    }

    public double getSflow_bbytes() {
        if (sfCount <= 0) return 0;
        return (double) this.backwardBytes / sfCount;
    }

    public double getSflow_bpackets() {
        if (sfCount <= 0) return 0;
        return (double) this.backward.size() / sfCount;
    }

    void detectUpdateSubflows(BasicPacketInfo packet) {
        if (sfLastPacketTS == -1) {
            sfLastPacketTS = packet.getTimeStamp();
            sfAcHelper = packet.getTimeStamp();
        }
        //System.out.print(" - "+(packet.timeStamp - sfLastPacketTS));
        if(((packet.getTimeStamp() - sfLastPacketTS)/(double)1000000)  > 1.0){
            sfCount++;
            long lastSFduration = packet.getTimeStamp() - sfAcHelper;
            updateActiveIdleTime(packet.getTimeStamp(), this.activityTimeout);
            sfAcHelper = packet.getTimeStamp();
        }

        sfLastPacketTS = packet.getTimeStamp();
    }

    public void updateFlowBulk(BasicPacketInfo packet) {
        if (Arrays.equals(this.src, packet.getSrc())) {
            updateForwardBulk(packet, blastBulkTS);
        } else {
            updateBackwardBulk(packet,flastBulkTS);
        }
    }

    public void updateForwardBulk(BasicPacketInfo packet, long tsOflastBulkInOther) {

        long size = packet.getPayloadBytes();
        if (tsOflastBulkInOther > fbulkStartHelper) fbulkStartHelper = 0;
        if (size <= 0) return;

        packet.getPayloadPacket();

        if (fbulkStartHelper == 0) {
            fbulkStartHelper = packet.getTimeStamp();
            fbulkPacketCountHelper = 1;
            fbulkSizeHelper = size;
            flastBulkTS = packet.getTimeStamp();
        } //possible bulk
        else {
            // Too much idle time?
            if (((packet.getTimeStamp() - flastBulkTS) / (double) 1000000) > 1.0) {
                fbulkStartHelper = packet.getTimeStamp();
                flastBulkTS = packet.getTimeStamp();
                fbulkPacketCountHelper = 1;
                fbulkSizeHelper = size;
            }// Add to bulk
            else {
                fbulkPacketCountHelper += 1;
                fbulkSizeHelper += size;
                //New bulk
                if (fbulkPacketCountHelper == 4) {
                    fbulkStateCount += 1;
                    fbulkPacketCount += fbulkPacketCountHelper;
                    fbulkSizeTotal += fbulkSizeHelper;
                    fbulkDuration += packet.getTimeStamp() - fbulkStartHelper;
                } //Continuation of existing bulk
                else if (fbulkPacketCountHelper > 4) {
                    fbulkPacketCount += 1;
                    fbulkSizeTotal += size;
                    fbulkDuration += packet.getTimeStamp() - flastBulkTS;
                }
                flastBulkTS = packet.getTimeStamp();
            }
        }
    }

    public void updateBackwardBulk(BasicPacketInfo packet, long tsOflastBulkInOther) {
		/*bAvgBytesPerBulk =0;
		bbulkSizeTotal=0;
		bbulkStateCount=0;*/
        long size = packet.getPayloadBytes();
        if (tsOflastBulkInOther > bbulkStartHelper) bbulkStartHelper = 0;
        if (size <= 0) return;

        packet.getPayloadPacket();

        if (bbulkStartHelper == 0) {
            bbulkStartHelper = packet.getTimeStamp();
            bbulkPacketCountHelper = 1;
            bbulkSizeHelper = size;
            blastBulkTS = packet.getTimeStamp();
        } //possible bulk
        else {
            // Too much idle time?
            if (((packet.getTimeStamp() - blastBulkTS) / (double) 1000000) > 1.0) {
                bbulkStartHelper = packet.getTimeStamp();
                blastBulkTS = packet.getTimeStamp();
                bbulkPacketCountHelper = 1;
                bbulkSizeHelper = size;
            }// Add to bulk
            else {
                bbulkPacketCountHelper += 1;
                bbulkSizeHelper += size;
                //New bulk
                if (bbulkPacketCountHelper == 4) {
                    bbulkStateCount += 1;
                    bbulkPacketCount += bbulkPacketCountHelper;
                    bbulkSizeTotal += bbulkSizeHelper;
                    bbulkDuration += packet.getTimeStamp() - bbulkStartHelper;
                } //Continuation of existing bulk
                else if (bbulkPacketCountHelper > 4) {
                    bbulkPacketCount += 1;
                    bbulkSizeTotal += size;
                    bbulkDuration += packet.getTimeStamp() - blastBulkTS;
                }
                blastBulkTS = packet.getTimeStamp();
            }
        }

    }

    public long fbulkStateCount() {
        return fbulkStateCount;
    }

    public long fbulkSizeTotal() {
        return fbulkSizeTotal;
    }

    public long fbulkPacketCount() {
        return fbulkPacketCount;
    }

    public long fbulkDuration() {
        return fbulkDuration;
    }

    public double fbulkDurationInSecond() {
        return fbulkDuration / (double) 1000000;
    }


    //Client average bytes per bulk
    public double fAvgBytesPerBulk() {
        if (this.fbulkStateCount() != 0)
            return ((double) this.fbulkSizeTotal() / this.fbulkStateCount());
        return 0;
    }


    //Client average packets per bulk
    public double fAvgPacketsPerBulk() {
        if (this.fbulkStateCount() != 0)
            return ((double) this.fbulkPacketCount() / this.fbulkStateCount());
        return 0;
    }


    //Client average bulk rate
    public double fAvgBulkRate() {
        if (this.fbulkDuration() != 0)
            return ((double) this.fbulkSizeTotal() / this.fbulkDurationInSecond());
        return 0;
    }


    //new features server
    public long bbulkPacketCount() {
        return bbulkPacketCount;
    }

    public long bbulkStateCount() {
        return bbulkStateCount;
    }

    public long bbulkSizeTotal() {
        return bbulkSizeTotal;
    }

    public long bbulkDuration() {
        return bbulkDuration;
    }

    public double bbulkDurationInSecond() {
        return bbulkDuration / (double) 1000000;
    }

    //Server average bytes per bulk
    public double bAvgBytesPerBulk() {
        if (this.bbulkStateCount() != 0)
            return ((double) this.bbulkSizeTotal() / this.bbulkStateCount());
        return 0;
    }

    //Server average packets per bulk
    public double bAvgPacketsPerBulk() {
        if (this.bbulkStateCount() != 0)
            return ((double) this.bbulkPacketCount() / this.bbulkStateCount());
        return 0;
    }

    //Server average bulk rate
    public double bAvgBulkRate() {
        if (this.bbulkDuration() != 0)
            return ((double) this.bbulkSizeTotal() / this.bbulkDurationInSecond());
        return 0;
    }

    ////////////////////////////


    public void updateActiveIdleTime(long currentTime, long threshold) {
        if ((currentTime - this.endActiveTime) > threshold) {
            if ((this.endActiveTime - this.startActiveTime) > 0) {
                this.flowActive.addValue(this.endActiveTime - this.startActiveTime);
            }
            this.flowIdle.addValue(currentTime - this.endActiveTime);
            this.startActiveTime = currentTime;
            this.endActiveTime = currentTime;
        } else {
            this.endActiveTime = currentTime;
        }
    }

    public void endActiveIdleTime(long currentTime, long threshold, long flowTimeOut, boolean isFlagEnd) {

        if ((this.endActiveTime - this.startActiveTime) > 0) {
            this.flowActive.addValue(this.endActiveTime - this.startActiveTime);
        }

        if (!isFlagEnd && ((flowTimeOut - (this.endActiveTime - this.flowStartTime)) > 0)) {
            this.flowIdle.addValue(flowTimeOut - (this.endActiveTime - this.flowStartTime));
        }
    }

    public int packetCount() {
        if (isBidirectional) {
            return (this.forward.size() + this.backward.size());
        } else {
            return this.forward.size();
        }
    }

    public List<BasicPacketInfo> getForward() {
        return new ArrayList<>(forward);
    }

    public void setForward(List<BasicPacketInfo> forward) {
        this.forward = forward;
    }

    public List<BasicPacketInfo> getBackward() {
        return new ArrayList<>(backward);
    }

    public void setBackward(List<BasicPacketInfo> backward) {
        this.backward = backward;
    }

    public boolean isBidirectional() {
        return isBidirectional;
    }

    public void setBidirectional(boolean isBidirectional) {
        this.isBidirectional = isBidirectional;
    }

    public byte[] getSrc() {
        return Arrays.copyOf(src, src.length);
    }

    public void setSrc(byte[] src) {
        this.src = src;
    }

    public byte[] getDst() {
        return Arrays.copyOf(dst, dst.length);
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

    public String getProtocolStr() {
        switch (this.protocol.val) {
            case (6):
                return "TCP";
            case (17):
                return "UDP";
        }
        return "UNKNOWN";
    }

    public long getFlowStartTime() {
        return flowStartTime;
    }

    public void setFlowStartTime(long flowStartTime) {
        this.flowStartTime = flowStartTime;
    }

    public String getFlowId() {
        return flowId;
    }

    public void setFlowId(String flowId) {
        this.flowId = flowId;
    }

    public long getLastSeen() {
        return flowLastSeen;
    }

    public void setLastSeen(long lastSeen) {
        this.flowLastSeen = lastSeen;
    }

    public long getStartActiveTime() {
        return startActiveTime;
    }

    public void setStartActiveTime(long startActiveTime) {
        this.startActiveTime = startActiveTime;
    }

    public long getEndActiveTime() {
        return endActiveTime;
    }

    public void setEndActiveTime(long endActiveTime) {
        this.endActiveTime = endActiveTime;
    }

    public String getSrcIP() {
        return FormatUtils.ip(src);
    }

    public String getDstIP() {
        return FormatUtils.ip(dst);
    }

    public String getTimeStamp() {
        return DateFormatter.parseDateFromLong(flowStartTime / 1000L, "dd/MM/yyyy hh:mm:ss");
    }

    public long getFlowDuration() {
        return flowLastSeen - flowStartTime;
    }

    public long getTotalFwdPackets() {
        return fwdPktStats.getN();
    }

    public long getTotalBackwardPackets() {
        return bwdPktStats.getN();
    }

    public double getTotalLengthofFwdPackets() {
        return fwdPktStats.getSum();
    }

    public double getTotalLengthofBwdPackets() {
        return bwdPktStats.getSum();
    }

    public double getFwdPacketLengthMax() {
        return (fwdPktStats.getN() > 0L) ? fwdPktStats.getMax() : 0;
    }

    public double getFwdPacketLengthMin() {
        return (fwdPktStats.getN() > 0L) ? fwdPktStats.getMin() : 0;
    }

    public double getFwdPacketLengthMean() {
        return (fwdPktStats.getN() > 0L) ? fwdPktStats.getMean() : 0;
    }

    public double getFwdPacketLengthStd() {
        return (fwdPktStats.getN() > 0L) ? fwdPktStats.getStandardDeviation() : 0;
    }

    public double getBwdPacketLengthMax() {
        return (bwdPktStats.getN() > 0L) ? bwdPktStats.getMax() : 0;
    }

    public double getBwdPacketLengthMin() {
        return (bwdPktStats.getN() > 0L) ? bwdPktStats.getMin() : 0;
    }

    public double getBwdPacketLengthMean() {
        return (bwdPktStats.getN() > 0L) ? bwdPktStats.getMean() : 0;
    }

    public double getBwdPacketLengthStd() {
        return (bwdPktStats.getN() > 0L) ? bwdPktStats.getStandardDeviation() : 0;
    }

    public double getFlowBytesPerSec() {
        //flow duration is in microseconds, therefore packets per seconds = packets / (duration/1000000)
        return ((double) (forwardBytes + backwardBytes)) / ((double) getFlowDuration() / 1000000L);
    }

    public double getFlowPacketsPerSec() {
        return ((double) packetCount()) / ((double) getFlowDuration() / 1000000L);
    }

    public SummaryStatistics getFlowIAT() {
        return flowIAT;
    }

    public double getFwdIATTotal() {
        return (forward.size() > 1) ? forwardIAT.getSum() : 0;
    }

    public double getFwdIATMean() {
        return (forward.size() > 1) ? forwardIAT.getMean() : 0;
    }

    public double getFwdIATStd() {
        return (forward.size() > 1) ? forwardIAT.getStandardDeviation() : 0;
    }

    public double getFwdIATMax() {
        return (forward.size() > 1) ? forwardIAT.getMax() : 0;
    }

    public double getFwdIATMin() {
        return (forward.size() > 1) ? forwardIAT.getMin() : 0;
    }

    public double getBwdIATTotal() {
        return (backward.size() > 1) ? backwardIAT.getSum() : 0;
    }

    public double getBwdIATMean() {
        return (backward.size() > 1) ? backwardIAT.getMean() : 0;
    }

    public double getBwdIATStd() {
        return (backward.size() > 1) ? backwardIAT.getStandardDeviation() : 0;
    }

    public double getBwdIATMax() {
        return (backward.size() > 1) ? backwardIAT.getMax() : 0;
    }

    public double getBwdIATMin() {
        return (backward.size() > 1) ? backwardIAT.getMin() : 0;
    }

    // get flag count for one specific flag in the fwd direction
    // e.g., flow.getFwdFlagCount("SYN") returns how many packets that had the SYN flag active went fwd
    public int getFwdFlagCount(String key) {
        return fwdFlagCounts.get(key).value;
    }

    // get flag count for one specific flag in the bwd direction
    public int getBwdFlagCount(String key) {
        return bwdFlagCounts.get(key).value;
    }

    // get total flag count across both directions (derived, not stored separately)
    // e.g., flow.getFlagCount("ACK") = fwd ACK count + bwd ACK count
    public int getFlagCount(String key) {
        return fwdFlagCounts.get(key).value + bwdFlagCounts.get(key).value;
    }

    // convenience getters kept for backward compatibility in case there's other code that 
    // still calls the old names (though it shouldn't be the case) commented out right below
    // they now just delegate to the 3 new hashmap-based getters right above
    public int getFwdPSHFlags() { 
        return getFwdFlagCount("PSH"); 
    }
    
    public int getBwdPSHFlags() { 
        return getBwdFlagCount("PSH"); 
    }
    
    public int getFwdURGFlags() { 
        return getFwdFlagCount("URG"); 
    }
    
    public int getBwdURGFlags() { 
        return getBwdFlagCount("URG"); 
    }
    
    public int getFwdFINFlags() { 
        return getFwdFlagCount("FIN"); 
    }
    
    public int getBwdFINFlags() { 
        return getBwdFlagCount("FIN"); 
    }

    /* 
    public int getFwdPSHFlags() {
        return fPSH_cnt;
    }

    public int getBwdPSHFlags() {
        return bPSH_cnt;
    }

    public int getFwdURGFlags() {
        return fURG_cnt;
    }

    public int getBwdURGFlags() {
        return bURG_cnt;
    }

    public int getFwdFINFlags() {
        return fFIN_cnt;
    }

    public int getBwdFINFlags() {
        return bFIN_cnt;
    }

    // redefined above
    public int getFlagCount(String key) {
        return flagCounts.get(key).value;
    }

    */

    public long getFwdHeaderLength() {
        return fHeaderBytes;
    }

    public long getBwdHeaderLength() {
        return bHeaderBytes;
    }

    public double getMinPacketLength() {
        return (forward.size() > 0 || backward.size() > 0) ? flowLengthStats.getMin() : 0;
    }

    public double getMaxPacketLength() {
        return (forward.size() > 0 || backward.size() > 0) ? flowLengthStats.getMax() : 0;
    }

    public double getPacketLengthMean() {
        return (forward.size() > 0 || backward.size() > 0) ? flowLengthStats.getMean() : 0;
    }

    public double getPacketLengthStd() {
        return (forward.size() > 0 || backward.size() > 0) ? flowLengthStats.getStandardDeviation() : 0;
    }

    public double getPacketLengthVariance() {
        return (forward.size() > 0 || backward.size() > 0) ? flowLengthStats.getVariance() : 0;
    }

    public int getInit_Win_bytes_forward() {
        return Init_Win_bytes_forward;
    }

    public int getInit_Win_bytes_backward() {
        return Init_Win_bytes_backward;
    }

    public long getAct_data_pkt_forward() {
        return Act_data_pkt_forward;
    }

    public long getAct_data_pkt_backward() {
        return Act_data_pkt_backward;
    }

    public long getmin_seg_size_forward() {
        return min_seg_size_forward;
    }

    public long getmin_seg_size_backward() {
        return min_seg_size_backward;
    }

    public double getActiveMean() {
        return (flowActive.getN() > 0) ? flowActive.getMean() : 0;
    }

    public double getActiveStd() {
        return (flowActive.getN() > 0) ? flowActive.getStandardDeviation() : 0;
    }

    public double getActiveMax() {
        return (flowActive.getN() > 0) ? flowActive.getMax() : 0;
    }

    public double getActiveMin() {
        return (flowActive.getN() > 0) ? flowActive.getMin() : 0;
    }

    public double getIdleMean() {
        return (flowIdle.getN() > 0) ? flowIdle.getMean() : 0;
    }

    public double getIdleStd() {
        return (flowIdle.getN() > 0) ? flowIdle.getStandardDeviation() : 0;
    }

    public double getIdleMax() {
        return (flowIdle.getN() > 0) ? flowIdle.getMax() : 0;
    }

    public double getIdleMin() {
        return (flowIdle.getN() > 0) ? flowIdle.getMin() : 0;
    }

    public TcpFlowState getTcpFlowState() {
        return this.tcpFlowState;
    }

    public void setTcpFlowState(TcpFlowState state) {
        this.tcpFlowState = state;
    }

    public long getCumulativeConnectionDuration() {
        return this.cumulativeConnectionDuration;
    }

    public void setCumulativeConnectionDuration(long cumCnxDuration) {
        this.cumulativeConnectionDuration = cumCnxDuration;
    }

    public Set<TcpRetransmissionDTO> getTcpPacketsSeen() {
        return this.tcpPacketsSeen;
    }

    public void setTcpPacketsSeen(Set<TcpRetransmissionDTO> tcpPacketsSeen) {
        this.tcpPacketsSeen = tcpPacketsSeen;
    }

    public int getIcmpCode() {
        return this.icmpCode;
    }

    public int getIcmpType() {
        return this.icmpType;
    }


    public String getLabel() {
        //the original is "|". I think it should be "||" need to check,
		/*if(FormatUtils.ip(src).equals("147.32.84.165") || FormatUtils.ip(dst).equals("147.32.84.165")){
			return "BOTNET";
		}
		else{
			return "BENIGN";
		}*/
        return "NeedManualLabel";
    }

    public String dumpFlowBasedFeaturesEx() {
        StringBuilder dump = new StringBuilder();

        dump.append(flowId).append(separator);                                        //1
        dump.append(FormatUtils.ip(src)).append(separator);                        //2
        dump.append(getSrcPort()).append(separator);                                //3
        dump.append(FormatUtils.ip(dst)).append(separator);                        //4
        dump.append(getDstPort()).append(separator);                                //5
        dump.append(getProtocol().val).append(separator);                                //6

        String starttime = DateFormatter.convertEpochTimestamp2String(flowStartTime);
        dump.append(starttime).append(separator);                                    //7

        long flowDuration = flowLastSeen - flowStartTime;
        dump.append(flowDuration).append(separator);                                //8

        dump.append(fwdPktStats.getN()).append(separator);                            //9
        dump.append(bwdPktStats.getN()).append(separator);                            //10
        dump.append(fwdPktStats.getSum()).append(separator);                        //11
        dump.append(bwdPktStats.getSum()).append(separator);                        //12

        if (fwdPktStats.getN() > 0L) {
            dump.append(fwdPktStats.getMax()).append(separator);                    //13
            dump.append(fwdPktStats.getMin()).append(separator);                    //14
            dump.append(fwdPktStats.getMean()).append(separator);                    //15
            dump.append(fwdPktStats.getStandardDeviation()).append(separator);        //16
        } else {
            dump.append(0).append(separator);
            dump.append(0).append(separator);
            dump.append(0).append(separator);
            dump.append(0).append(separator);
        }

        if (bwdPktStats.getN() > 0L) {
            dump.append(bwdPktStats.getMax()).append(separator);                    //17
            dump.append(bwdPktStats.getMin()).append(separator);                    //18
            dump.append(bwdPktStats.getMean()).append(separator);                    //19
            dump.append(bwdPktStats.getStandardDeviation()).append(separator);        //20
        } else {
            dump.append(0).append(separator);
            dump.append(0).append(separator);
            dump.append(0).append(separator);
            dump.append(0).append(separator);
        }

        if(flowDuration != 0){
            dump.append(((double) (forwardBytes + backwardBytes)) / ((double) flowDuration / 1000000L)).append(separator); //21
            dump.append(((double) packetCount()) / ((double) flowDuration / 1000000L)).append(separator); // 22
        }else{
            dump.append(-1).append(separator);
            dump.append(-1).append(separator);
        }

        dump.append(Double.isNaN(flowIAT.getMean()) ? 0 : flowIAT.getMean()).append(separator);  // 23
        dump.append(Double.isNaN(flowIAT.getStandardDeviation()) ? 0 : flowIAT.getStandardDeviation()).append(separator); //24
        dump.append(Double.isNaN(flowIAT.getMax()) ? 0 : flowIAT.getMax()).append(separator);    //25
        dump.append(Double.isNaN(flowIAT.getMin()) ? 0 : flowIAT.getMin()).append(separator);                         //26

        if (this.forward.size() > 1) {
            dump.append(forwardIAT.getSum()).append(separator);                        //27
            dump.append(forwardIAT.getMean()).append(separator);                    //28
            dump.append(forwardIAT.getStandardDeviation()).append(separator);        //29
            dump.append(forwardIAT.getMax()).append(separator);                        //30
            dump.append(forwardIAT.getMin()).append(separator);                        //31

        } else {
            dump.append(0).append(separator);
            dump.append(0).append(separator);
            dump.append(0).append(separator);
            dump.append(0).append(separator);
            dump.append(0).append(separator);
        }
        if (this.backward.size() > 1) {
            dump.append(backwardIAT.getSum()).append(separator);                    //32
            dump.append(backwardIAT.getMean()).append(separator);                    //33
            dump.append(backwardIAT.getStandardDeviation()).append(separator);        //34
            dump.append(backwardIAT.getMax()).append(separator);                    //35
            dump.append(backwardIAT.getMin()).append(separator);                    //36
        } else {
            dump.append(0).append(separator);
            dump.append(0).append(separator);
            dump.append(0).append(separator);
            dump.append(0).append(separator);
            dump.append(0).append(separator);
        }

        dump.append(fHeaderBytes).append(separator);                                //43
        dump.append(bHeaderBytes).append(separator);                                //44
        dump.append(getfPktsPerSecond()).append(separator);                            //45
        dump.append(getbPktsPerSecond()).append(separator);                            //46


        if (this.forward.size() > 0 || this.backward.size() > 0) {
            dump.append(flowLengthStats.getMin()).append(separator);                //47
            dump.append(flowLengthStats.getMax()).append(separator);                //48
            dump.append(flowLengthStats.getMean()).append(separator);                //49
            dump.append(flowLengthStats.getStandardDeviation()).append(separator);    //50
            dump.append(flowLengthStats.getVariance()).append(separator);            //51
        } else {//seem to less one
            dump.append(0).append(separator);
            dump.append(0).append(separator);
            dump.append(0).append(separator);
            dump.append(0).append(separator);
            dump.append(0).append(separator);
        }

		/*for(MutableInt v:flagCounts.values()) {
			dump.append(v).append(separator);
		}
		for(String key: flagCounts.keySet()){
			dump.append(flagCounts.get(key).value).append(separator);				//50,51,52,53,54,55,56,57
		} */

        // fwd flag counts
        dump.append(fwdFlagCounts.get("FIN").value).append(separator);  // fwd FIN
        dump.append(fwdFlagCounts.get("SYN").value).append(separator);  // fwd SYN
        dump.append(fwdFlagCounts.get("RST").value).append(separator);  // fwd RST
        dump.append(fwdFlagCounts.get("PSH").value).append(separator);  // fwd PSH
        dump.append(fwdFlagCounts.get("ACK").value).append(separator);  // fwd ACK
        dump.append(fwdFlagCounts.get("URG").value).append(separator);  // fwd URG
        dump.append(fwdFlagCounts.get("CWR").value).append(separator);  // fwd CWR
        dump.append(fwdFlagCounts.get("ECE").value).append(separator);  // fwd ECE

        // bwd flag counts
        dump.append(bwdFlagCounts.get("FIN").value).append(separator);  // bwd FIN
        dump.append(bwdFlagCounts.get("SYN").value).append(separator);  // bwd SYN
        dump.append(bwdFlagCounts.get("RST").value).append(separator);  // bwd RST
        dump.append(bwdFlagCounts.get("PSH").value).append(separator);  // bwd PSH
        dump.append(bwdFlagCounts.get("ACK").value).append(separator);  // bwd ACK
        dump.append(bwdFlagCounts.get("URG").value).append(separator);  // bwd URG
        dump.append(bwdFlagCounts.get("CWR").value).append(separator);  // bwd CWR
        dump.append(bwdFlagCounts.get("ECE").value).append(separator);  // bwd ECE

        // total flag count (derived from fwd and bwd flag counts) 
        dump.append(getFlagCount("FIN")).append(separator);  // total FIN
        dump.append(getFlagCount("SYN")).append(separator);  // total SYN
        dump.append(getFlagCount("RST")).append(separator);  // total RST
        dump.append(getFlagCount("PSH")).append(separator);  // total PSH
        dump.append(getFlagCount("ACK")).append(separator);  // total ACK
        dump.append(getFlagCount("URG")).append(separator);  // total URG
        dump.append(getFlagCount("CWR")).append(separator);  // total CWR
        dump.append(getFlagCount("ECE")).append(separator);  // total ECE

        dump.append(getDownUpRatio()).append(separator);                            //60
        dump.append(getAvgPacketSize()).append(separator);                            //61
        dump.append(fAvgSegmentSize()).append(separator);                            //62
        dump.append(bAvgSegmentSize()).append(separator);                            //63
        //dump.append(fHeaderBytes).append(separator);								//62 dupicate with 43

        dump.append(fAvgBytesPerBulk()).append(separator);                            //64
        dump.append(fAvgPacketsPerBulk()).append(separator);                        //65
        dump.append(fAvgBulkRate()).append(separator);                                //66
        dump.append(bAvgBytesPerBulk()).append(separator);                            //67
        dump.append(bAvgPacketsPerBulk()).append(separator);                        //68
        dump.append(bAvgBulkRate()).append(separator);                                //69

        dump.append(getSflow_fpackets()).append(separator);                            //70
        dump.append(getSflow_fbytes()).append(separator);                            //71
        dump.append(getSflow_bpackets()).append(separator);                            //72
        dump.append(getSflow_bbytes()).append(separator);                            //73

        dump.append(Init_Win_bytes_forward).append(separator);                        //74
        dump.append(Init_Win_bytes_backward).append(separator);                        //75
        dump.append(Act_data_pkt_forward).append(separator);                            //76
        dump.append(Act_data_pkt_backward).append(separator);                           //77
        dump.append(min_seg_size_forward).append(separator);                        //78
        dump.append(min_seg_size_backward).append(separator);                       //79


        if (this.flowActive.getN() > 0) {
            dump.append(flowActive.getMean()).append(separator);                    //80
            dump.append(flowActive.getStandardDeviation()).append(separator);        //81
            dump.append(flowActive.getMax()).append(separator);                        //82
            dump.append(flowActive.getMin()).append(separator);                        //83
        } else {
            dump.append(0).append(separator);
            dump.append(0).append(separator);
            dump.append(0).append(separator);
            dump.append(0).append(separator);
        }

        if (this.flowIdle.getN() > 0) {
            dump.append(flowIdle.getMean()).append(separator);                        //84
            dump.append(flowIdle.getStandardDeviation()).append(separator);            //85
            dump.append(flowIdle.getMax()).append(separator);                        //86
            dump.append(flowIdle.getMin()).append(separator);                        //87
        } else {
            dump.append(0).append(separator);
            dump.append(0).append(separator);
            dump.append(0).append(separator);
            dump.append(0).append(separator);
        }

        dump.append(icmpCode).append(separator);                                    // 88
        dump.append(icmpType).append(separator);                                    // 89

        dump.append(fwdTcpRetransCnt).append(separator);                                    // 88
        dump.append(bwdTcpRetransCnt).append(separator);                                    // 89
        dump.append(fwdTcpRetransCnt+bwdTcpRetransCnt).append(separator);                   // 90

        dump.append(cumulativeConnectionDuration).append(separator);                //91
        dump.append(getLabel());                                                    //92

        return dump.toString();
    }
}

class MutableInt {
    int value = 0; // note that we start at 1 since we're counting

    public void increment() {
        ++value;
    }

    public int get() {
        return value;
    }


}
