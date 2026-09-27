use std::collections::HashMap;
use std::process::Command;
use std::thread;
use std::time::Duration;

use sysinfo::System;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;


const FIREFOX_PATH: &str =
    r"C:\Program Files\Mozilla Firefox\firefox.exe";


enum NetworkDecision {
    Allow,
    Block,
}


fn check_policy(program: &str) -> NetworkDecision {
    if program.eq_ignore_ascii_case(FIREFOX_PATH) {
        NetworkDecision::Allow
    } else {
        NetworkDecision::Block
    }
}


// ---------------------------------------------------------
// Convert a Rust string into a Windows UTF-16 string
// ---------------------------------------------------------

fn to_wide_string(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}


// ---------------------------------------------------------
// Add one WFP filter
// ---------------------------------------------------------

unsafe fn add_filter(
    engine: HANDLE,
    layer: windows::core::GUID,
    sublayer: windows::core::GUID,
    action: FWP_ACTION_TYPE,
    weight: u8,
    condition: Option<FWPM_FILTER_CONDITION0>,
) -> Result<u64, u32> {

    let filter_key =
        windows::core::GUID::new().map_err(|_| 1u32)?;

    let mut conditions = condition
        .map(|condition| vec![condition])
        .unwrap_or_default();







            
    let mut filter = FWPM_FILTER0::default();

    let filter_name = to_wide_string("Rust Network Lock Filter");

    filter.displayData.name =
        PWSTR::from_raw(filter_name.as_ptr() as *mut u16);

    filter.filterKey = filter_key;
    filter.layerKey = layer;
    filter.subLayerKey = sublayer;




        
    filter.filterKey = filter_key;
    filter.layerKey = layer;
    filter.subLayerKey = sublayer;

    filter.weight = FWP_VALUE0 {
        r#type: FWP_UINT8,
        Anonymous: FWP_VALUE0_0 {
            uint8: weight,
        },
    };

    filter.action = FWPM_ACTION0 {
        r#type: action,
        Anonymous: FWPM_ACTION0_0::default(),
    };

    if !conditions.is_empty() {
        filter.numFilterConditions = conditions.len() as u32;
        filter.filterCondition = conditions.as_mut_ptr();
    }

    let mut filter_id: u64 = 0;

    let result = unsafe {
        FwpmFilterAdd0(
            engine,
            &filter,
            None,
            Some(&mut filter_id),
        )
    };
    if result == 0 {
        Ok(filter_id)
    } else {
        Err(result)
    }
}


// ---------------------------------------------------------
// Install Firefox-only outbound policy
// ---------------------------------------------------------

unsafe fn install_network_lock(
    engine: HANDLE,
) -> Result<(), u32> {

    println!("Installing WFP network policy...");
    println!();

    // -----------------------------------------------------
    // Get Firefox application ID
    // -----------------------------------------------------

    let wide_path = to_wide_string(FIREFOX_PATH);

    let mut firefox_app_id: *mut FWP_BYTE_BLOB =
        std::ptr::null_mut();


    let result = unsafe {
        FwpmGetAppIdFromFileName0(
            PCWSTR::from_raw(wide_path.as_ptr()),
            &mut firefox_app_id,
        )
    };

    if result != 0 {
        println!("Failed to get Firefox application ID.");
        println!("Windows error code: {}", result);

        return Err(result);
    }

    println!("Firefox application ID: READY");


    // -----------------------------------------------------
    // Build Firefox application condition
    // -----------------------------------------------------

    let firefox_condition = FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_ALE_APP_ID,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_BYTE_BLOB_TYPE,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                byteBlob: firefox_app_id,
            },
        },
    };


    // -----------------------------------------------------
    // Use Microsoft's universal WFP sublayer
    // -----------------------------------------------------

    let sublayer = FWPM_SUBLAYER_UNIVERSAL;


    // -----------------------------------------------------
    // Firefox PERMIT
    //
    // Weight 15 = high priority
    // -----------------------------------------------------

    println!("Adding Firefox IPv4 permit filter...");





    match unsafe {
        add_filter(
            engine,
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            sublayer,
            FWP_ACTION_PERMIT,
            15,
            Some(firefox_condition),
        )
    } {
        Ok(id) => {
            println!("Firefox IPv4 PERMIT installed.");
            println!("Filter ID: {}", id);
        }

        Err(error) => {
            println!("Firefox IPv4 permit FAILED.");
            println!("Windows error code: {}", error);

        unsafe {
            FwpmFreeMemory0(
                &mut (firefox_app_id as *mut std::ffi::c_void)
            );
        }

            return Err(error);
        }
    }


    // -----------------------------------------------------
    // Firefox IPv6 PERMIT
    // -----------------------------------------------------

    println!("Adding Firefox IPv6 permit filter...");

    let firefox_condition_v6 = FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_ALE_APP_ID,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_BYTE_BLOB_TYPE,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                byteBlob: firefox_app_id,
            },
        },
    };

    match unsafe {
        add_filter(
            engine,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            sublayer,
            FWP_ACTION_PERMIT,
            15,
            Some(firefox_condition_v6),
        )
    } {
        Ok(id) => {
            println!("Firefox IPv6 PERMIT installed.");
            println!("Filter ID: {}", id);
        }

        Err(error) => {
            println!("Firefox IPv6 permit FAILED.");
            println!("Windows error code: {}", error);

            unsafe {
                FwpmFreeMemory0(
                    &mut (firefox_app_id as *mut std::ffi::c_void)
                );
            }

            return Err(error);
        }
    }


    // -----------------------------------------------------
    // BLOCK EVERYTHING ELSE IPv4
    //
    // No condition = matches all outbound connections.
    //
    // Weight 0 = lower than Firefox's weight 15.
    // -----------------------------------------------------

    println!("Adding IPv4 BLOCK-ALL filter...");

    match unsafe {
        add_filter(
            engine,
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            sublayer,
            FWP_ACTION_BLOCK,
            0,
            None,
        )
    } {
        Ok(id) => {
            println!("IPv4 BLOCK-ALL installed.");
            println!("Filter ID: {}", id);
        }

        Err(error) => {
            println!("IPv4 BLOCK-ALL FAILED.");
            println!("Windows error code: {}", error);

            unsafe {
                FwpmFreeMemory0(
                    &mut (firefox_app_id as *mut std::ffi::c_void)
                );
            }

            return Err(error);
        }
    }


    // -----------------------------------------------------
    // BLOCK EVERYTHING ELSE IPv6
    // -----------------------------------------------------

    println!("Adding IPv6 BLOCK-ALL filter...");

    match unsafe {
        add_filter(
            engine,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            sublayer,
            FWP_ACTION_BLOCK,
            0,
            None,
        )
    } {
        Ok(id) => {
            println!("IPv6 BLOCK-ALL installed.");
            println!("Filter ID: {}", id);
        }

        Err(error) => {
            println!("IPv6 BLOCK-ALL FAILED.");
            println!("Windows error code: {}", error);

        unsafe {
            FwpmFreeMemory0(
                &mut (firefox_app_id as *mut std::ffi::c_void)
            );
        }

            return Err(error);
        }
    }


    // -----------------------------------------------------
    // Free application ID memory
    // -----------------------------------------------------

    unsafe {
        FwpmFreeMemory0(
            &mut (firefox_app_id as *mut std::ffi::c_void)
        );
    }


    println!();
    println!("======================================");
    println!("WFP NETWORK LOCK ACTIVE");
    println!("======================================");
    println!("ALLOW:");
    println!("  {}", FIREFOX_PATH);
    println!();
    println!("BLOCK:");
    println!("  Everything else");
    println!("======================================");
    println!();

    Ok(())
}


// ---------------------------------------------------------
// Main
// ---------------------------------------------------------

fn main() {

    println!("Rust Network Lock");
    println!("-----------------");
    println!();

    println!("Opening WFP dynamic session...");


    unsafe {

        // -------------------------------------------------
        // Create dynamic WFP session
        // -------------------------------------------------

        let mut session = FWPM_SESSION0::default();

        session.flags = FWPM_SESSION_FLAG_DYNAMIC;

        let mut engine_handle = HANDLE::default();


        let result = FwpmEngineOpen0(
            None,
            RPC_C_AUTHN_DEFAULT as u32,
            None,
            Some(&session as *const FWPM_SESSION0),
            &mut engine_handle,
        );


        if result != 0 {

            println!("WFP engine: FAILED");
            println!("Windows error code: {}", result);

            return;
        }


        println!("WFP engine: OPEN");
        println!();


        // -------------------------------------------------
        // Install actual network enforcement
        // -------------------------------------------------

        match install_network_lock(engine_handle) {

            Ok(_) => {}

            Err(_) => {

                println!();
                println!("Network lock installation failed.");
                println!("Closing WFP engine.");

                FwpmEngineClose0(engine_handle);

                return;
            }
        }


        // -------------------------------------------------
        // Existing network monitor
        // -------------------------------------------------

        loop {

            // ---------------------------------------------
            // Refresh running processes
            // ---------------------------------------------

            let mut system = System::new_all();

            system.refresh_all();


            // ---------------------------------------------
            // Build PID -> process information
            // ---------------------------------------------

            let mut process_table:
                HashMap<u32, (String, String)> =
                HashMap::new();


            for process in system.processes().values() {

                let pid =
                    process.pid().as_u32();

                let name =
                    process.name()
                        .to_string_lossy()
                        .to_string();

                let path =
                    match process.exe() {

                        Some(path) =>
                            path.to_string_lossy()
                                .to_string(),

                        None =>
                            String::from("UNKNOWN"),
                    };


                process_table.insert(
                    pid,
                    (name, path),
                );
            }


            // ---------------------------------------------
            // Read network connections
            // ---------------------------------------------

            let output =
                Command::new("netstat")
                    .args(["-ano"])
                    .output()
                    .expect("Failed to run netstat");


            let results =
                String::from_utf8_lossy(
                    &output.stdout
                );


            println!("Process-aware network connections:");
            println!();


            // ---------------------------------------------
            // Examine TCP connections
            // ---------------------------------------------

            for line in results.lines() {

                let parts:
                    Vec<&str> =
                    line.split_whitespace()
                        .collect();


                if parts.len() != 5 ||
                   parts[0] != "TCP"
                {
                    continue;
                }


                let local_address =
                    parts[1];

                let remote_address =
                    parts[2];

                let state =
                    parts[3];

                let pid_text =
                    parts[4];


                let pid: u32 =
                    match pid_text.parse() {

                        Ok(pid) => pid,

                        Err(_) => continue,
                    };


                // -----------------------------------------
                // Look up PID
                // -----------------------------------------

                match process_table.get(&pid) {

                    Some((name, path)) => {

                        let decision =
                            check_policy(path);


                        let policy =
                            match decision {

                                NetworkDecision::Allow =>
                                    "ALLOW",

                                NetworkDecision::Block =>
                                    "BLOCK",
                            };


                        let connection_type =
                            match state {

                                "ESTABLISHED" =>
                                    "ACTIVE",

                                "LISTENING" =>
                                    "LISTENING",

                                "TIME_WAIT" =>
                                    "TIME_WAIT",

                                "CLOSE_WAIT" =>
                                    "CLOSE_WAIT",

                                _ =>
                                    "OTHER",
                            };


                        println!(
                            "PID {:>6} | {:<18} | {:<22} -> {:<22} | {:<12} | {:<9} | {}",
                            pid,
                            name,
                            local_address,
                            remote_address,
                            state,
                            connection_type,
                            policy
                        );
                    }


                    None => {

                        println!(
                            "PID {:>6} | PROCESS NOT FOUND | {:<22} -> {:<22} | {}",
                            pid,
                            local_address,
                            remote_address,
                            state
                        );
                    }
                }
            }


            println!();
            println!("NETWORK LOCK ACTIVE");
            println!("Firefox: ALLOW");
            println!("Everything else: BLOCK");
            println!();
            println!("Next scan in 2 seconds...");
            println!();


            thread::sleep(
                Duration::from_secs(2)
            );
        }
    }
}