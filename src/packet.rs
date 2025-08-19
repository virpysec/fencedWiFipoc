use std::collections::HashSet;
use std::fmt::{self, Formatter};
use std::io::{Cursor, Read};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose;
use base64::Engine;
use byteorder::{ByteOrder, LittleEndian as LE, ReadBytesExt};

// Error decoding packet: UnknownRadioTapLength(0)

/// All the possible packet types for 802.11.
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, Default)]
pub enum Packet_Name {
    /// Management Packet. Type: 0, Subtype: 0
    Association_Request,
    /// Management Packet. Type: 0, Subtype: 1
    Association_Response,
    /// Management Packet. Type: 0, Subtype: 2
    Reassociation_Request,
    /// Management Packet. Type: 0, Subtype: 3
    Reassociation_Response,
    /// Management Packet. Type: 0, Subtype: 4
    Probe_Request,
    /// Management Packet. Type: 0, Subtype: 5
    Probe_Response,
    /// Management Packet. Type: 0, Subtype: 6
    Timing_Advertisement,
    /// Management Packet. Type: 0, Subtype: 8
    Beacon,
    /// Management Packet. Type: 0, Subtype: 9
    ATIM,
    /// Management Packet. Type: 0, Subtype: 10
    Disassociation,
    /// Management Packet. Type: 0, Subtype: 11
    Authentication,
    /// Management Packet. Type: 0, Subtype: 12
    Deauthentication,
    /// Management Packet. Type: 0, Subtype: 13
    Action,
    /// Management Packet. Type: 0, Subtype: 14
    Action_No_Ack,
    /// Control Packet. Type: 1, Subtype: 2
    Trigger,
    /// Control Packet. Type: 1, Subtype: 3
    TACK,
    /// Control Packet. Type: 1, Subtype: 4
    Beamforming_Report_Poll,
    /// Control Packet. Type: 1, Subtype: 5
    VHT_HE_NDP_Announcement,
    /// Control Packet. Type: 1, Subtype: 6
    Control_Frame_Extension,
    /// Control Packet. Type: 1, Subtype: 7
    Control_Wrapper,
    /// Control Packet. Type: 1, Subtype: 8
    Block_Ack_Request,
    /// Control Packet. Type: 1, Subtype: 9
    Block_Ack,
    /// Control Packet. Type: 1, Subtype: 10
    PS_Poll,
    /// Control Packet. Type: 1, Subtype: 11
    RTS,
    /// Control Packet. Type: 1, Subtype: 12
    CTS,
    /// Control Packet. Type: 1, Subtype: 13
    ACK,
    /// Control Packet. Type: 1, Subtype: 14
    CF_End,
    /// Control Packet. Type: 1, Subtype: 15
    CF_End_CF_ACK,
    /// Data Packet. Type: 2, Subtype: 0
    Data,
    /// Data Packet. Type: 2, Subtype: 4
    Null,
    /// Data Packet. Type: 2, Subtype: 8
    QoS_Data,
    /// Data Packet. Type: 2, Subtype: 9
    QoS_Data_CF_ACK,
    /// Data Packet. Type: 2, Subtype: 10
    QoS_Data_CF_Poll,
    /// Data Packet. Type: 2, Subtype: 11
    QoS_Data_CF_ACK_CF_Poll,
    /// Data Packet. Type: 2, Subtype: 12
    QoS_Null,
    /// Data Packet. Type: 2, Subtype: 14
    QoS_CF_Poll,
    /// Data Packet. Type: 2, Subtype: 15
    QoS_CF_ACK_CF_Poll,
    /// Extension Packet. Type: 3, Subtype: 0
    DMGBeacon,
    /// Reserved Packet which can be either a Management, Control, Data or Extension Type.
    Reserved,
    /// Unknown Packet Type and Subtype.
    #[default]
    Unknown,
}

/// Possible errors that could occur while decoding a packet.
#[derive(Debug, Clone)]
pub enum PacketError {
    /// RadioTap Header length was different than normal.
    /// Will eventually get to the length.
    UnknownRadioTapLength(usize),
    /// Error while decoding one the RadioTap Header.
    RadioTapError,
    /// Error while trying to decode the Frame Control.
    FrameControlError,
    /// Error while trying to write the packet to a pcap file.
    PcapWriterError(String),
    /// Error while trying to Base64 decoding the SSID.
    SSIDDecodeError(String),
    /// Packet type and subtype are not known.
    UnknownPacket(String),
    /// Unknown Error.
    Unknown(String),
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            PacketError::RadioTapError => {
                write!(f, "Error has occurred while decoding the RadioTap Header.")
            }
            PacketError::UnknownRadioTapLength(e) => {
                write!(f, "Unknown RadioTap Header Length: {e}")
            }
            PacketError::FrameControlError => {
                write!(f, "Error has occurred while decoding the Frame Control.")
            }
            PacketError::PcapWriterError(e) => {
                write!(f, "Error occurred while writing the pcap.\n{e}")
            }
            PacketError::SSIDDecodeError(e) => write!(f, "Couldn't Base64 decode the SSID: {e}."),
            PacketError::UnknownPacket(e) => write!(f, "Packet is Unknown.\n{e}"),
            PacketError::Unknown(e) => write!(f, "Unknown error has occurred.\n{e}"),
        }
    }
}

impl fmt::Display for Packet_Name {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Packet_Name::Association_Request => write!(f, "Association Request"),
            Packet_Name::Association_Response => write!(f, "Association Response"),
            Packet_Name::Reassociation_Request => write!(f, "Reassociation Request"),
            Packet_Name::Reassociation_Response => write!(f, "Reassociation Response"),
            Packet_Name::Probe_Request => write!(f, "Probe Request"),
            Packet_Name::Probe_Response => write!(f, "Probe Response"),
            Packet_Name::Timing_Advertisement => write!(f, "Timing Advertisement"),
            Packet_Name::Beacon => write!(f, "Beacon"),
            Packet_Name::ATIM => write!(f, "ATIM"),
            Packet_Name::Disassociation => write!(f, "Disassociation"),
            Packet_Name::Authentication => write!(f, "Authentication"),
            Packet_Name::Deauthentication => write!(f, "Deauthentication"),
            Packet_Name::Action => write!(f, "Action"),
            Packet_Name::Action_No_Ack => write!(f, "Action No Ack (NACK)"),
            Packet_Name::Trigger => write!(f, "Trigger"),
            Packet_Name::TACK => write!(f, "TACK"),
            Packet_Name::Beamforming_Report_Poll => write!(f, "Beamforming Report Poll"),
            Packet_Name::VHT_HE_NDP_Announcement => write!(f, "VHT/HE NDP Announcement"),
            Packet_Name::Control_Frame_Extension => write!(f, "Control Frame Extension"),
            Packet_Name::Control_Wrapper => write!(f, "Control Wrapper"),
            Packet_Name::Block_Ack_Request => write!(f, "Block Ack Request"),
            Packet_Name::Block_Ack => write!(f, "Block Ack"),
            Packet_Name::PS_Poll => write!(f, "PS-Poll"),
            Packet_Name::RTS => write!(f, "RTS"),
            Packet_Name::CTS => write!(f, "CTS"),
            Packet_Name::ACK => write!(f, "ACK"),
            Packet_Name::CF_End => write!(f, "CF-End"),
            Packet_Name::CF_End_CF_ACK => write!(f, "CF-End + CF-ACK"),
            Packet_Name::Data => write!(f, "Data"),
            Packet_Name::Null => write!(f, "Null (no data)"),
            Packet_Name::QoS_Data => write!(f, "QoS Data"),
            Packet_Name::QoS_Data_CF_ACK => write!(f, "QoS Data + CF-ACK"),
            Packet_Name::QoS_Data_CF_Poll => write!(f, "QoS Data + CF-Poll"),
            Packet_Name::QoS_Data_CF_ACK_CF_Poll => write!(f, "QoS Data + CF-ACK + CF-Poll"),
            Packet_Name::QoS_Null => write!(f, "QoS Null (no data)"),
            Packet_Name::QoS_CF_Poll => write!(f, "QoS CF-Poll (no data)"),
            Packet_Name::QoS_CF_ACK_CF_Poll => write!(f, "QoS CF-ACK + CF-Poll (no data)"),
            Packet_Name::DMGBeacon => write!(f, "DMG Beacon"),
            Packet_Name::Reserved => write!(f, "Reserved"),
            Packet_Name::Unknown => write!(f, "Unknown"),
        }
    }
}

impl Packet_Name {
    pub fn new(pt: u16, ps: u16) -> Self {
        match (pt, ps) {
            (0, 0) => Packet_Name::Association_Request,
            (0, 1) => Packet_Name::Association_Response,
            (0, 2) => Packet_Name::Reassociation_Request,
            (0, 3) => Packet_Name::Reassociation_Response,
            (0, 4) => Packet_Name::Probe_Request,
            (0, 5) => Packet_Name::Probe_Response,
            (0, 6) => Packet_Name::Timing_Advertisement,
            (0, 7) => Packet_Name::Reserved,
            (0, 8) => Packet_Name::Beacon,
            (0, 9) => Packet_Name::ATIM,
            (0, 10) => Packet_Name::Disassociation,
            (0, 11) => Packet_Name::Authentication,
            (0, 12) => Packet_Name::Deauthentication,
            (0, 13) => Packet_Name::Action,
            (0, 14) => Packet_Name::Action_No_Ack,
            (0, 15) => Packet_Name::Reserved,
            (1, 0) => Packet_Name::Reserved,
            (1, 1) => Packet_Name::Reserved,
            (1, 2) => Packet_Name::Trigger,
            (1, 3) => Packet_Name::TACK,
            (1, 4) => Packet_Name::Beamforming_Report_Poll,
            (1, 5) => Packet_Name::VHT_HE_NDP_Announcement,
            (1, 6) => Packet_Name::Control_Frame_Extension,
            (1, 7) => Packet_Name::Control_Wrapper,
            (1, 8) => Packet_Name::Block_Ack_Request,
            (1, 9) => Packet_Name::Block_Ack,
            (1, 10) => Packet_Name::PS_Poll,
            (1, 11) => Packet_Name::RTS,
            (1, 12) => Packet_Name::CTS,
            (1, 13) => Packet_Name::ACK,
            (1, 14) => Packet_Name::CF_End,
            (1, 15) => Packet_Name::CF_End_CF_ACK,
            (2, 0) => Packet_Name::Data,
            (2, 1) => Packet_Name::Reserved,
            (2, 2) => Packet_Name::Reserved,
            (2, 3) => Packet_Name::Reserved,
            (2, 4) => Packet_Name::Null,
            (2, 5) => Packet_Name::Reserved,
            (2, 6) => Packet_Name::Reserved,
            (2, 7) => Packet_Name::Reserved,
            (2, 8) => Packet_Name::QoS_Data,
            (2, 9) => Packet_Name::QoS_Data_CF_ACK,
            (2, 10) => Packet_Name::QoS_Data_CF_Poll,
            (2, 11) => Packet_Name::QoS_Data_CF_ACK_CF_Poll,
            (2, 12) => Packet_Name::QoS_Null,
            (2, 13) => Packet_Name::Reserved,
            (2, 14) => Packet_Name::QoS_CF_Poll,
            (2, 15) => Packet_Name::QoS_CF_ACK_CF_Poll,
            (3, 0) => Packet_Name::DMGBeacon,
            _ => Packet_Name::Unknown,
        }
    }
}

// Different Flag that could be present in the RadioTap Header.
#[derive(Debug)]
enum PresentFlags {
    TSFT,
    Flags,
    Rate,
    Channel,
    FHSS,
    AntennaSignal,
    AntennaNoise,
    LockQuality,
    TxAttenuation,
    TxAttenuationDb,
    TxPower,
    Antenna,
    AntennaSignalDb,
    AntennaNoiseDb,
    RxFlags,
    TxFlags,
    RTSRetries,
    DataRetries,
    XChannel,
    MCS,
    AMPDUStatus,
    VHT,
    Timestamp,
}

impl PresentFlags {
    fn new(bit: i32) -> Option<PresentFlags> {
        match bit {
            0 => Some(PresentFlags::TSFT),
            1 => Some(PresentFlags::Flags),
            2 => Some(PresentFlags::Rate),
            3 => Some(PresentFlags::Channel),
            4 => Some(PresentFlags::FHSS),
            5 => Some(PresentFlags::AntennaSignal),
            6 => Some(PresentFlags::AntennaNoise),
            7 => Some(PresentFlags::LockQuality),
            8 => Some(PresentFlags::TxAttenuation),
            9 => Some(PresentFlags::TxAttenuationDb),
            10 => Some(PresentFlags::TxPower),
            11 => Some(PresentFlags::Antenna),
            12 => Some(PresentFlags::AntennaSignalDb),
            13 => Some(PresentFlags::AntennaNoiseDb),
            14 => Some(PresentFlags::RxFlags),
            15 => Some(PresentFlags::TxFlags),
            16 => Some(PresentFlags::RTSRetries),
            17 => Some(PresentFlags::DataRetries),
            18 => Some(PresentFlags::XChannel),
            19 => Some(PresentFlags::MCS),
            20 => Some(PresentFlags::AMPDUStatus),
            21 => Some(PresentFlags::VHT),
            22 => Some(PresentFlags::Timestamp),
            _ => None,
        }
    }
}

// Take the frequency and turns it to a channel.
fn get_channel(freq: u16) -> u8 {
    match freq {
        2412 => 1,
        2417 => 2,
        2422 => 3,
        2427 => 4,
        2432 => 5,
        2437 => 6,
        2442 => 7,
        2447 => 8,
        2452 => 9,
        2457 => 10,
        2462 => 11,
        2467 => 12,
        2472 => 13,
        2484 => 14,
        5180 => 36,
        5200 => 40,
        5220 => 44,
        5240 => 48,
        5260 => 52,
        5280 => 56,
        5300 => 60,
        5320 => 64,
        5500 => 100,
        5520 => 104,
        5540 => 108,
        5560 => 112,
        5600 => 120,
        5620 => 124,
        5640 => 128,
        5660 => 132,
        5680 => 136,
        5700 => 140,
        5720 => 144,
        5745 => 149,
        5765 => 153,
        5785 => 157,
        5805 => 161,
        5825 => 165,
        _ => 0,
    }
}

// Gets the present flags for a RadioTap Header with a length of 18.
fn get_present(pf: u32) -> Vec<PresentFlags> {
    let mut present_flags: Vec<PresentFlags> = vec![];
    for bit in 0..29 {
        if pf & (1 << bit) != 0 {
            if let Some(x) = PresentFlags::new(bit) {
                present_flags.push(x);
            }
        }
    }
    present_flags
}

// Decoding a RadioTap Header with a length of 18.
fn length_18(curs: &mut Cursor<&[u8]>) -> Result<(i8, u8), PacketError> {
    let mut freq: u16 = 0;
    let mut signal: i8 = 0;
    let mut _present_flag: Vec<PresentFlags> = get_present(curs.read_u32::<LE>().unwrap());

    for i in _present_flag.into_iter() {
        match i {
            PresentFlags::TSFT => curs.set_position(curs.position() + 8),
            PresentFlags::Flags => curs.set_position(curs.position() + 1),
            PresentFlags::Rate => curs.set_position(curs.position() + 1),
            PresentFlags::Channel => {
                freq = curs
                    .read_u16::<LE>()
                    .map_err(|_| PacketError::RadioTapError)?;
                curs.set_position(curs.position() + 2);
            }
            PresentFlags::FHSS => curs.set_position(curs.position() + 2),
            PresentFlags::AntennaSignal => {
                signal = curs.read_i8().map_err(|_| PacketError::RadioTapError)?;
                break;
            }
            _ => (),
        }
    }

    curs.set_position(18);
    Ok((signal, get_channel(freq)))
}

// Decoding a RadioTap Header with a length of 21.
fn length_21(curs: &mut Cursor<&[u8]>) -> Result<(i8, u8), PacketError> {
    curs.set_position(curs.position() + 6);

    let freq: u16 = curs
        .read_u16::<LE>()
        .map_err(|_| PacketError::RadioTapError)?;

    curs.set_position(curs.position() + 2);

    let signal: i8 = curs.read_i8().map_err(|_| PacketError::RadioTapError)?;

    curs.set_position(21);
    Ok((signal, get_channel(freq)))
}

// Decoding a RadioTap Header with a length of 24.
fn length_24(curs: &mut Cursor<&[u8]>) -> Result<(i8, u8), PacketError> {
    curs.set_position(curs.position() + 10);

    let freq: u16 = curs
        .read_u16::<LE>()
        .map_err(|_| PacketError::RadioTapError)?;

    curs.set_position(curs.position() + 2);

    let signal: i8 = curs.read_i8().map_err(|_| PacketError::RadioTapError)?;

    curs.set_position(24);
    Ok((signal, get_channel(freq)))
}

// Decoding a RadioTap Header with a length of 27.
fn length_27(curs: &mut Cursor<&[u8]>) -> Result<(i8, u8), PacketError> {
    curs.set_position(curs.position() + 9);

    let freq: u16 = curs
        .read_u16::<LE>()
        .map_err(|_| PacketError::RadioTapError)?;

    curs.set_position(curs.position() + 2);

    let signal: i8 = curs.read_i8().map_err(|_| PacketError::RadioTapError)?;

    curs.set_position(27);
    Ok((signal, get_channel(freq)))
}

// Decoding a RadioTap Header with a length of 38.
fn length_38(curs: &mut Cursor<&[u8]>) -> Result<(i8, u8), PacketError> {
    curs.set_position(curs.position() + 9);

    let freq: u16 = curs
        .read_u16::<LE>()
        .map_err(|_| PacketError::RadioTapError)?;

    curs.set_position(curs.position() + 2);

    let signal: i8 = curs.read_i8().map_err(|_| PacketError::RadioTapError)?;

    curs.set_position(38);
    Ok((signal, get_channel(freq)))
}

// Decoding a RadioTap Header with a length of 46.
fn length_46(curs: &mut Cursor<&[u8]>) -> Result<(i8, u8), PacketError> {
    curs.set_position(curs.position() + 9);

    let freq: u16 = curs
        .read_u16::<LE>()
        .map_err(|_| PacketError::RadioTapError)?;

    curs.set_position(curs.position() + 2);

    let signal: i8 = curs.read_i8().map_err(|_| PacketError::RadioTapError)?;

    curs.set_position(46);
    Ok((signal, get_channel(freq)))
}

/// Parses the RadioTap Header. Returns a Result of either a tuple of (signal, channel) or a PacketError.
pub fn parse_rtap(curs: &mut Cursor<&[u8]>) -> Result<(i8, u8), PacketError> {
    curs.set_position(curs.position() + 2);
    let length: usize = curs.read_u16::<LE>().unwrap() as usize;
    match length {
        18 => length_18(curs),
        21 => length_21(curs),
        24 => length_24(curs),
        27 => length_27(curs),
        38 => length_38(curs),
        46 => length_46(curs),
        _ => Err(PacketError::UnknownRadioTapLength(length)),
    }
}

/// This Packet struct holds all the information about a decoded packet.
#[derive(Clone, Default, Debug)]
pub struct Packet {
    /// Packet name determined from the pkt_type and pkt_subtype.
    pub pkt_name: Packet_Name,
    /// Packet type tell the type of packet it is.
    /// 0 = Management Packet
    /// 1 = Control Packet
    /// 2 = Data Packet
    pub pkt_type: u16,
    /// Packet subtype tell the subtype of packet it is.
    /// For more information visit <https://community.cisco.com/t5/wireless-mobility-knowledge-base/802-11-frames-a-starter-guide-to-learn-wireless-sniffer-traces/ta-p/3110019>
    pub pkt_subtype: u16,
    /// The toDS field tells if packet was sent from a device to the AP station.
    /// 0 = False
    /// 1 = True
    pub to_ds: u16,
    /// The FromDS field tells if packet was sent from a AP station to the device.
    /// 0 = False
    /// 1 = True
    pub frm_ds: u16,
    /// Signal from the RadioTap Header.
    pub signal: i8,
    /// Channel that the packet was sniffed on.
    pub channel: u8,
    /// Destination Address (DA) : Final recipient of the frame
    pub addr1: String,
    /// Source Address (SA) : Original source of the frame
    pub addr2: String,
    /// Receiver Address (RA) : Immediate receiver of the frame.
    pub addr3: String,
    /// Transmitter Address (TA) : Immediate sender of the frame.
    pub addr4: String,
    /// Service Set Identifier.
    /// Will be Base64 Encoded if the ssid is not utf-8 with a b64- at the beginning.
    pub ssid: String,
    /// The Raw Packet.
    pub raw_pkt: Vec<u8>,
}

impl fmt::Display for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Packet {{\n\tpkt_name: {:?},\n\tpkt_type: {},\n\tpkt_subtype: {},\n\tto_ds: {},\n\tfrm_ds: {},\n\t\
            signal: {},\n\tchannel: {},\n\taddr1: {},\n\taddr2: {},\n\taddr3: {},\n\taddr4: {},\n\tssid: {}\n}}",
            self.pkt_name, self.pkt_type, self.pkt_subtype, self.to_ds, self.frm_ds, self.signal, self.channel,
            self.addr1, self.addr2, self.addr3, self.addr4, self.ssid
        )
    }
}

impl Packet {
    pub fn new(pkt: &[u8]) -> Result<Packet, PacketError> {
        let mut curs: Cursor<&[u8]> = Cursor::new(pkt);

        // Parsing the RadioTap Header to get the Signal and Channel.
        let (signal, channel) = parse_rtap(&mut curs)?;

        // Parsing the Frame Control.
        let (pkt_type, pkt_subtype, to_ds, frm_ds, pkt_name) = frame_control(&mut curs)?;

        // Parsing the Mac
        let (addr1, addr2, addr3, addr4, ssid) = match pkt_type {
            0 => match pkt_subtype {
                0 => get_macs_and_ssid(&mut curs, 4),
                4 => get_macs_and_ssid(&mut curs, 2),
                8 | 5 => get_macs_and_ssid(&mut curs, 14),
                1..=3 | 7 | 9..=15 => get_macs(&mut curs, 3),
                _ => {
                    return Err(PacketError::UnknownPacket(format!(
                        "Packet Type: {pkt_type}, Subtype: {pkt_subtype}"
                    )))
                }
            },
            1 => match pkt_subtype {
                8..=9 | 11..=13 => get_macs(&mut curs, 2),
                0..=7 | 10 | 14 | 15 => get_macs(&mut curs, 3),
                _ => {
                    return Err(PacketError::UnknownPacket(format!(
                        "Packet Type: {pkt_type}, Subtype: {pkt_subtype}"
                    )))
                }
            },
            2 => {
                if to_ds == 1 && frm_ds == 1 {
                    get_macs(&mut curs, 4)
                } else {
                    get_macs(&mut curs, 3)
                }
            }
            3 => match pkt_subtype {
                0 => {
                    curs.set_position(curs.position() + 2);
                    let mac: String = read_mac(&mut curs);
                    (
                        none_address(),
                        mac,
                        none_address(),
                        none_address(),
                        none_address(),
                    )
                }
                _ => {
                    return Err(PacketError::UnknownPacket(format!(
                        "Packet Type: {pkt_type}, Subtype: {pkt_subtype}"
                    )))
                }
            },
            _ => {
                return Err(PacketError::UnknownPacket(format!(
                    "Packet Type: {pkt_type}, Subtype: {pkt_subtype}"
                )))
            }
        };

        let raw_pkt: Vec<u8> = pkt.to_vec();

        Ok(Packet {
            pkt_name,
            pkt_type,
            pkt_subtype,
            to_ds,
            frm_ds,
            signal,
            channel,
            addr1,
            addr2,
            addr3,
            addr4,
            ssid,
            raw_pkt,
        })
    }
    /// Parses a raw packet into a `Packet` instance.

    /// Returns a `HashSet` of unique MAC addresses.
    pub fn hashset_addresses(&self) -> HashSet<String> {
        HashSet::from([
            self.addr1.clone(),
            self.addr2.clone(),
            self.addr3.clone(),
            self.addr4.clone(),
        ])
    }
}

// Gets the System Time and turns it into Seconds and Microseconds.
// Used for writing the packet to the pcap file.
fn create_time() -> (u64, u32) {
    let sys_time: SystemTime = SystemTime::now();

    let duration: Duration = match sys_time.duration_since(UNIX_EPOCH) {
        Ok(t) => t,
        Err(_) => return (0, 0),
    };

    let sec: u64 = duration.as_secs();
    let usec: u32 = duration.subsec_micros();
    (sec, usec)
}

fn none_address() -> String {
    String::from("None")
}

fn unknown_ssid() -> String {
    String::from("***U_n_k_n_o_w_n***")
}

fn read_mac(curs: &mut Cursor<&[u8]>) -> String {
    curs.read_u48::<LE>()
        .map_or_else(|_| none_address(), mac_address)
}

// Turns the u64 in to a readable mac.
fn mac_address(x: u64) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        x as u8,
        (x >> 8) as u8,
        (x >> 16) as u8,
        (x >> 24) as u8,
        (x >> 32) as u8,
        (x >> 40) as u8
    )
}

// Checks to see if there are any None Printable Characters in the SSID
fn check_for_printable(ssid: &str) -> bool {
    for char in ssid.chars() {
        if !char.is_ascii() {
            return false;
        }
    }
    true
}

// Loops through the Information Elements till the ssid if found.
fn find_ssid(curs: &mut Cursor<&[u8]>) -> String {
    let mut ssid: String = unknown_ssid();

    loop {
        let element_id: u8 = match curs.read_u8() {
            Ok(val) => val,
            Err(_) => break,
        };

        let element_len: u8 = match curs.read_u8() {
            Ok(val) => val,
            Err(_) => break,
        };

        if element_id != 0 {
            curs.set_position(curs.position() + element_len as u64);
            continue;
        }

        ssid = get_ssid(element_len, curs);
        break;
    }

    ssid
}

// Parses the SSID Information Element to get the SSID.
fn get_ssid(length: u8, curs: &mut Cursor<&[u8]>) -> String {
    match length {
        0 => unknown_ssid(),
        _ => {
            // Creating a Vector of 0 the length of size of the ssid.
            let mut ssid_bytes: Vec<u8> = vec![0; length as usize];

            // Extracting the ssid and writing it to the ssid_bytes vec.
            match curs.read_exact(&mut ssid_bytes[0..length as usize]) {
                Ok(_) => (),
                Err(_) => return unknown_ssid(),
            };

            let mut ssid: String =
                String::from_utf8_lossy(&ssid_bytes[0..length as usize]).to_string();

            // Checking to see if the ssid has printable characters.
            // If not then base64 encode the ssid and add b64- to the front.
            if !check_for_printable(&ssid) {
                ssid = format!("b64-{}", general_purpose::STANDARD.encode(ssid))
            }

            if is_ssid_all_null(&ssid) {
                ssid = unknown_ssid();
            }

            ssid
        }
    }
}

// Checks all the characters of the ssid to see if they are all null characters.
fn is_ssid_all_null(ssid: &str) -> bool {
    for byte in ssid.bytes() {
        if byte != 0 {
            return false;
        }
    }
    true
}

// Decodes the Frame Control from the packet. Returns the packet type, packet subtype, toDS and fromDS.
fn frame_control(
    curs: &mut Cursor<&[u8]>,
) -> Result<(u16, u16, u16, u16, Packet_Name), PacketError> {
    let fc = curs
        .read_u16::<LE>()
        .map_err(|_| PacketError::RadioTapError)?;

    let pkt_type: u16 = (fc & 0b0000_0000_0000_1100) >> 2;
    let pkt_subtype: u16 = (fc & 0b0000_0000_1111_0000) >> 4;
    let to_ds: u16 = (fc & 0b0000_0001_0000_0000) >> 8;
    let frm_ds: u16 = (fc & 0b0000_0010_0000_0000) >> 9;
    Ok((
        pkt_type,
        pkt_subtype,
        to_ds,
        frm_ds,
        Packet_Name::new(pkt_type, pkt_subtype),
    ))
}

fn get_macs_and_ssid(
    curs: &mut Cursor<&[u8]>,
    jump: u64,
) -> (String, String, String, String, String) {
    let (addr1, addr2, addr3, addr4, _) = get_macs(curs, 3);
    // Getting the ssid Information and ssid.
    curs.set_position(curs.position() + jump);
    let ssid: String = find_ssid(curs);
    (addr1, addr2, addr3, addr4, ssid)
}

fn get_macs(curs: &mut Cursor<&[u8]>, how_many: u8) -> (String, String, String, String, String) {
    curs.set_position(curs.position() + 2);
    let addr1: String = read_mac(curs);
    let addr2: String = read_mac(curs);
    let mut addr3: String = none_address();
    let mut addr4: String = none_address();
    match how_many {
        3 => addr3 = read_mac(curs),
        4 => {
            addr3 = read_mac(curs);
            curs.set_position(curs.position() + 2);
            addr4 = read_mac(curs);
        }
        _ => (),
    }

    (addr1, addr2, addr3, addr4, none_address())
}