/*
 * Created by brightSPARK Labs
 * www.brightsparklabs.com
 */

package com.brightsparklabs.insilico.standin.export;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.sql.Timestamp;
import java.util.logging.Logger;

import com.brightsparklabs.asanti.model.data.AsnData;
import com.brightsparklabs.asanti.reader.AsnBerFileReader;
import com.google.common.collect.ImmutableList;
import com.google.common.io.BaseEncoding;

public class EtsiToPcapExporter
{

    // -------------------------------------------------------------------------
    // CONSTANTS
    // -------------------------------------------------------------------------

    private static final String TAG_CC_PAYLOAD = "/2/1";
    private static final String TAG_CC_CONTENTS = "/2/1/2";

    private static final String TAG_IPCC_CONTENT = "/2/1/2/2/1/0";
    // Pattern PATTERN_IPCC = Pattern.compile(TAG_IPCC + "/\\d+.*");
    private static final String TAG_UMTSCC_CONTENT = "/2/1/2/4";
    private static final String TAG_PPP_CONTENT = "/2/1/2/6/4";
    // Pattern PATTERN_PPP = Pattern.compile(TAG_PPP + "/\\d+.*");
    private static final String TAG_ETHERNET_CONTENT = "/2/1/2/6/5";
    // Pattern PATTERN_ETHERNET = Pattern.compile(TAG_ETHERNET + "/\\d+.*");
    private static final String TAG_IPMMCC_CONTENT = "/2/1/2/12/1";
    // Pattern PATTERN_IPMMCC = Pattern.compile(TAG_IPMMCC_CONTENT + "/\\d+.*");
    private static final String TAG_EMAIL_CONTENT = "/2/1/2/1/2";
    private static final String TAG_EPSCC_CONTENT = "/2/1/2/15";
    // Pattern PATTERN_EPSCC = Pattern.compile(TAG_EPSCC + "/\\d+.*");

    /** magic number for PCAP Header */
    private static final byte[] MAGIC_NUMBER = { (byte) 0xA1, (byte) 0xB2, (byte) 0xC3, (byte) 0xD4 };

    /** major version for PCAP Header */
    private static final byte[] MAJOR_VERSION = { 0x00, 0x02 };

    /** minor version for PCAP Header */
    private static final byte[] MINOR_VERSION = { 0x00, 0x04 };

    /** maximum history to check for duplicate packets */
    private static final int DUPLICATE_CHECK_WINDOW_SIZE = 200;

    /** offset in seconds from GMT/UTC */
    private static final int GMT_OFFSET = 0;

    /** accuracy of timestamps (generally set to 0) */
    private static final int TIMESTAMP_ACCURACY = 0;

    /** maximum captured packet size */
    private static final int SNAP_LENGTH = 65535;

    // -------------------------------------------------------------------------
    // CLASS VARIABLES
    // -------------------------------------------------------------------------

    /** class logger */
    private static Logger log = Logger.getLogger(EtsiToPcapExporter.class.getName());

    // -------------------------------------------------------------------------
    // PUBLIC METHODS
    // -------------------------------------------------------------------------

    public static void main(String[] args) throws IOException
    {
        final File pcapFile = EtsiToPcapExporter.export(new File(args[0]));
        log.info("PCAP file exported to: " + pcapFile.getAbsolutePath());
    }

    public static File export(File etsiFile) throws IOException
    {
        final ImmutableList<AsnData> pdus = AsnBerFileReader.read(etsiFile);
        final File pcapFile = File.createTempFile(etsiFile.getName(), ".pcap");
        final BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(pcapFile));

        final AsnData firstPdu = pdus.get(0);
        for (final String rawTag : firstPdu.getRawTags())
        {
        }

        // write global header
        final LinkLayer linkLayer = getLinkLayer(firstPdu);
        final byte[] header = generateGlobalHeader(GMT_OFFSET, TIMESTAMP_ACCURACY, SNAP_LENGTH, linkLayer);
        out.write(header);

        // write each PDU
        for (final AsnData pdu : pdus)
        {
            final byte[] packets = generatePcapPacket(pdu);
            out.write(packets);
        }

        out.close();
        return pcapFile;
    }

    // -------------------------------------------------------------------------
    // PRIVATE METHODS
    // -------------------------------------------------------------------------

    private static LinkLayer getLinkLayer(AsnData pdu)
    {
        return pdu.contains(TAG_IPCC_CONTENT) ? LinkLayer.RAW
                : pdu.contains(TAG_IPMMCC_CONTENT) ? LinkLayer.RAW
                        : pdu.contains(TAG_IPCC_CONTENT) ? LinkLayer.RAW
                                : pdu.contains(TAG_EPSCC_CONTENT) ? LinkLayer.RAW
                                        : pdu.contains(TAG_PPP_CONTENT) ? LinkLayer.PPP
                                                : LinkLayer.Null;
    }

    /**
     * Returns a byte[] containing a PCAP Global/File Header formatted with the
     * specified values.
     *
     * byte[] conforms to the following c struct:
     *
     * typedef struct pcap_hdr_s { guint32 magic_number; -- magic number guint16
     * version_major; -- major version number guint16 version_minor; -- minor
     * version number gint32 thiszone; -- GMT to local correction (seconds)
     * guint32 sigfigs; -- accuracy of timestamps (always set to 0) guint32
     * snaplen; -- max length of captured packets, in octets guint32 network; --
     * data link type } pcap_hdr_t;
     *
     * @param gmtOffset
     *            In seconds. Maps to thiszone in the PCAP global header.
     * @param timestampAccuracy
     *            Usually set to 0. Maps to sigfis in the PCAP global header.
     * @param snapLen
     *            Max captured packet. Usually set to 65535. Maps to snaplen in
     *            PCAP global header.
     * @param linkLayer
     *            Layer that was intercepted. Maps to network in the PCAP global
     *            header.
     *
     * @return byte[] containing the packet record in PCAP format.
     */
    private static byte[] generateGlobalHeader(int gmtOffset, int timestampAccuracy, int snapLen, LinkLayer linkLayer)
    {
        final byte[] result = new byte[24];
        System.arraycopy(MAGIC_NUMBER, 0, result, 0, 4);
        System.arraycopy(MAJOR_VERSION, 0, result, 4, 2);
        System.arraycopy(MINOR_VERSION, 0, result, 6, 2);

        final ByteBuffer buf = ByteBuffer.allocate(4);
        buf.putInt(gmtOffset);
        System.arraycopy(buf.array(), 0, result, 8, 4);

        toUInt32(timestampAccuracy, result, 12);
        toUInt32(snapLen, result, 16);
        toUInt32(linkLayer.getValue(), result, 20);

        return result;
    }

    /**
     * Put an unsigned 32 bit value stored in a long into a byte array at the
     * specified index.
     *
     * @param val
     *            a long containing a UInt32 value to be stored.
     * @param buf
     *            the byte array in which to store the UInt32 value.
     * @param i
     *            the index of the array element to store the new value in.
     */
    private static void toUInt32(long val, byte buf[], int i)
    {
        buf[i] = (byte) ((val & 0xFF000000L) >> 24);
        buf[i + 1] = (byte) ((val & 0x00FF0000L) >> 16);
        buf[i + 2] = (byte) ((val & 0x0000FF00L) >> 8);
        buf[i + 3] = (byte) (val & 0x000000FFL);
    }

    /**
     * Creates a PCAP packet (header + payload)
     *
     * @param timestamp
     *            timestamp to use in packet
     * @param payload
     *            payload to include in packet
     *
     * @return byte[] PCAP formatted packet containing payload or an empty byte
     *         array if either parameter is {@code null}
     */
    private static byte[] generatePcapPacket(AsnData pdu)
    {
        final Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        // create and write PCAP packet
        final byte[] payload = getContent(pdu);

        final String hexString = BaseEncoding.base16().encode(payload);
        log.info("content: " + hexString);


        if (timestamp == null || payload == null || payload.length == 0) { return new byte[0]; }

        // will truncate instead of rounding
        final long seconds = timestamp.getTime() / 1000;
        final long microseconds = timestamp.getNanos() / 1000;

        final byte[] result = new byte[payload.length + 16];
        toUInt32(seconds, result, 0);
        toUInt32(microseconds, result, 4);
        toUInt32(payload.length, result, 8);
        // assume no truncation in packet length
        toUInt32(payload.length, result, 12);
        System.arraycopy(payload, 0, result, 16, payload.length);
        return result;
    }

    private static byte[] getContent(AsnData pdu)
    {
        return pdu.contains(TAG_IPCC_CONTENT) ? pdu.getBytes(TAG_IPCC_CONTENT)
                : pdu.contains(TAG_EPSCC_CONTENT) ? pdu.getBytes(TAG_EPSCC_CONTENT)
                        : pdu.contains(TAG_ETHERNET_CONTENT) ? pdu.getBytes(TAG_ETHERNET_CONTENT)
                                : pdu.contains(TAG_PPP_CONTENT) ? pdu.getBytes(TAG_PPP_CONTENT)
                                        : pdu.contains(TAG_IPMMCC_CONTENT) ? pdu.getBytes(TAG_IPMMCC_CONTENT)
                                                : pdu.contains(TAG_EMAIL_CONTENT) ? pdu.getBytes(TAG_EMAIL_CONTENT)
                                                        : pdu.contains(TAG_UMTSCC_CONTENT) ? pdu.getBytes(TAG_UMTSCC_CONTENT)
                                                                : new byte[0];
    }

    // -------------------------------------------------------------------------
    // INTERNAL ENUM DEFINITIONS
    // -------------------------------------------------------------------------
    /**
     * Defines the lowest captured protocol.
     *
     * Non BSD Defines from libpcap/pcap-bpf.h
     */
    public static enum LinkLayer
    {

        Null(0), // Loopback
        EN10MB(1), // 10Mb, 100Mb and 1Gb Ethernet
        EN3MB(2), // Experimental Ethernet
        AX25(3), // Amateur Radio
        PRONET(4), // Proteon ProNET Token Ring
        CHAOS(5), IEEE802(6), ARCNET(7), SLIP(8), PPP(9), FDDI(10), ATM_RFC1483(11), // LLC
                                                                                     // Encapsulated
                                                                                     // ATM
        RAW(12), // Raw IP
        SLIP_BSDOS(13), // BSD SLIP
        PPP_BSDOS(14), // BSD PPP
        ATM_CLIP(19), // IP over ATM */
        REDBACK_SMARTEDGE(32), PPP_SERIAL(50), // HDLC encapsualted
        PPP_ETHER(51), // PPPoE
        SYMANTEC_FIREWALL(99), C_HDLC(104), // Cisco HDLC
        IEEE802_11(105), // IEEE 802.11 Wireless
        FRELAY(107), // Frame Relay
        LOOP(108), // OpenBSD Loopback
        ENC(109), // Encapsulated packets for IPSec
        LINUX_SLL(113), // Linux cooked sockets
        LTALK(114), // Apple LocalTalk
        ECONET(115), // Acorn EcoNET
        IPFILTER(116), PFLOG(117), CISCO_IOS(118), PRISM_HEADER(119), // 802.11
                                                                      // with
                                                                      // Prism
                                                                      // II
                                                                      // chips
                                                                      // monitor
                                                                      // mode
        AIRONET_HEADER(120), HHDLC(121), // Siemiens HiPath HDLC
        IP_OVER_FC(122), SUNATM(123), // Solaris + SunATM
        RIO(124), // RapidIO
        PCI_EXP(125), // PCI Express
        AURORA(126), // Xilinx Aurora link layer
        IEEE802_11_RADIO(127), // 802.11 plus radiotap radio header
        TZSP(128), // Tazmen Sniffer Protocol
        ARCNET_LINUX(129), JUNIPER_MLPPP(130), JUNIPER_MLFR(131), JUNIPER_ES(132), JUNIPER_GGSN(133), JUNIPER_MFR(134), JUNIPER_ATM2(135), JUNIPER_SERVICES(
                136), JUNIPER_ATM1(137), APPLE_IP_OVER_IEEE1394(138), MTP2_WITH_PHDR(139), MTP2(140), MTP3(141), SCCP(142), DOCSIS(143), LINUX_IRDA(
                144), IBM_SP(145), IBM_SN(146),
        // 147 - 162 User defined
        IEEE802_11_RADIO_AVS(163), // 802.11 plus AVS radio header
        JUNIPER_MONITOR(164), BACNET_MS_TP(165), PPP_PPPD(166), JUNIPER_PPPOE(167), JUNIPER_PPPOE_ATM(168), GPRS_LLC(169), GPF_T(170), // GPF-T
                                                                                                                                       // (ITU-T
                                                                                                                                       // G.7041/Y.1303)
        GPF_F(171), // GPF-F (ITU-T G.7041/Y.1303)
        GCOM_T1E1(172), GCOM_SERIAL(173), JUNIPER_PIC_PEER(174), ERF_ETH(175), ERF_POS(176), LINUX_LAPD(177), JUNIPER_ETHER(178), JUNIPER_PPP(
                179), JUNIPER_FRELAY(180), JUNIPER_CHDLC(181);

        private final int value;

        LinkLayer(int value)
        {
            this.value = value;
        }

        public int getValue()
        {
            return value;
        }
    }
}
