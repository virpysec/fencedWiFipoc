use esp_idf_svc::{
    hal::prelude::Peripherals,
    sys::{
        wifi_promiscuous_pkt_t, wifi_promiscuous_pkt_type_t,
        wifi_promiscuous_pkt_type_t_WIFI_PKT_CTRL, wifi_promiscuous_pkt_type_t_WIFI_PKT_DATA,
        wifi_promiscuous_pkt_type_t_WIFI_PKT_MGMT, wifi_promiscuous_pkt_type_t_WIFI_PKT_MISC,
    },
};
use std::os::raw::c_void;
mod packet;
use packet::Packet;
use packet::PacketError;

const WIFI_PKT_MGMT: u32 = wifi_promiscuous_pkt_type_t_WIFI_PKT_MGMT;
const WIFI_PKT_DATA: u32 = wifi_promiscuous_pkt_type_t_WIFI_PKT_DATA;
const WIFI_PKT_CTRL: u32 = wifi_promiscuous_pkt_type_t_WIFI_PKT_CTRL;
const WIFI_PKT_MISC: u32 = wifi_promiscuous_pkt_type_t_WIFI_PKT_MISC;

extern "C" fn packet_handler( buf: *mut c_void, packet_type: wifi_promiscuous_pkt_type_t) {
    if buf.is_null() {
        return;
    }

    unsafe {
        let packet = &*(buf as *const wifi_promiscuous_pkt_t);
        let ctrl = &packet.rx_ctrl;

        let raw_pkt =
            std::slice::from_raw_parts(packet.payload.as_ptr(), packet.rx_ctrl.sig_len() as usize);

        match Packet::new(raw_pkt) {
            Ok(decoded_packet) => {
                println!("Decoded Packet: {:?}", decoded_packet);
            }
            Err(e) => {
                //println!("Error decoding packet: {:?}", e);
            }
        }

        match packet_type {
            WIFI_PKT_MGMT => {
                let payload_ptr = packet.payload.as_ptr() as *const u8;
                let payload_len = ctrl.sig_len() as usize;

                let payload = std::slice::from_raw_parts(payload_ptr, payload_len);

                if payload_len > 0 && payload[0] == 0x80 {
                    println!("Beacon frame captured: RSSI={}", ctrl.rssi());
                    parse_beacon_packet(payload_ptr, payload_len);

                    quick_mac_and_ssid_extract(payload);
                }
            }
            WIFI_PKT_DATA => {
                // println!(
                //     "Data frame captured: Length={}, RSSI={}",
                //     ctrl.sig_len(),
                //     ctrl.rssi(),

                // );
            }
            WIFI_PKT_CTRL => {
                println!(
                    "Control frame captured: Length={}, RSSI={}",
                    ctrl.sig_len(),
                    ctrl.rssi()
                );
            }
            WIFI_PKT_MISC => {
                println!(
                    "Miscellaneous frame captured: Length={}, RSSI={}",
                    ctrl.sig_len(),
                    ctrl.rssi()
                );
            }
            _ => {
                println!("Unknown frame type: {}", packet_type as u32);
            }
        }

    }

    //println!("raa ting: {}", packet_type as u32);
}

fn parse_beacon_packet(payload: *const u8, len: usize) {
    unsafe {
        let slice = std::slice::from_raw_parts(payload, len);
        //println!("Beacon Packet Data: {:?}", slice);
    }
}

fn extract_ssid(data: &[u8]) -> Option<String> {
    // Skip 802.11 header (24 bytes) + beacon fixed parameters (12 bytes) = 36 bytes
    let mut pos = 36;
    
    while pos + 2 < data.len() {
        let element_id = data[pos];
        let element_length = data[pos + 1] as usize;
        
        // Element ID 0 = SSID
        if element_id == 0 {
            if element_length == 0 {
                return Some("Hidden Network".to_string());
            }
            
            if pos + 2 + element_length <= data.len() {
                let ssid_bytes = &data[pos + 2..pos + 2 + element_length];
                let ssid = String::from_utf8_lossy(ssid_bytes).to_string();
                
                // Check if SSID is printable
                if ssid.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                    return Some(ssid);
                } else {
                    return Some(format!("Non-printable SSID (length: {})", element_length));
                }
            }
        }
        
        // Move to next element
        pos += 2 + element_length;
    }
    None
}

fn quick_mac_and_ssid_extract(data: &[u8]) {
    if data.len() >= 22 {
        // Extract MAC addresses
        println!("Addr1 (Dest): {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
                 data[4], data[5], data[6], data[7], data[8], data[9]);
        println!("Addr2 (Src):  {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
                 data[10], data[11], data[12], data[13], data[14], data[15]);
        println!("Addr3 (BSSID): {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
                 data[16], data[17], data[18], data[19], data[20], data[21]);
        
        // Extract SSID from beacon frame
        if data.len() > 36 && data[0] == 0x80 { // Check if it's a beacon frame
            if let Some(ssid) = extract_ssid(data) {
                println!("Network Name (SSID): {}", ssid);
            } else {
                println!("Network Name (SSID): Hidden/Unknown");
            }
        }
    }
}



fn main() {
    // It is necessary to call this function once. Otherwise some patches to the runtime
    // implemented by esp-idf-sys might not link properly. See https://github.com/esp-rs/esp-idf-template/issues/71
    esp_idf_svc::sys::link_patches();

    // Bind the log crate to the ESP Logging facilities
    esp_idf_svc::log::EspLogger::initialize_default();

    let peripherals = Peripherals::take().unwrap();
    let modem = peripherals.modem;
    let sysloop = esp_idf_svc::eventloop::EspSystemEventLoop::take().unwrap();
    let nvs = esp_idf_svc::nvs::EspDefaultNvsPartition::take().ok();

    let mut wifi = esp_idf_svc::wifi::EspWifi::new(modem, sysloop, nvs).unwrap();

    wifi.start().unwrap();

    let wifi_driver = wifi.driver_mut();

    unsafe {
        esp_idf_svc::sys::esp_wifi_set_promiscuous_rx_cb(Some(packet_handler));
    }

    wifi_driver.set_promiscuous(true).unwrap();

    log::info!("Hello, world!");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
