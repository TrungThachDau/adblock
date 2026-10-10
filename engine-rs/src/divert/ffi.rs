use std::ffi::c_void;
use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

pub type WinDivertHandle = *mut c_void;
pub const INVALID_HANDLE_VALUE: WinDivertHandle = -1isize as WinDivertHandle;

pub const WINDIVERT_LAYER_NETWORK: u32 = 0;
pub const WINDIVERT_PRIORITY_NORMAL: i16 = 0;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WinDivertAddress {
    pub timestamp: i64,
    pub bitfields: u64,
    pub data: [u8; 64],
}

impl Default for WinDivertAddress {
    fn default() -> Self {
        Self {
            timestamp: 0,
            bitfields: 0,
            data: [0u8; 64],
        }
    }
}

impl WinDivertAddress {
    pub fn is_outbound(&self) -> bool {
        (self.bitfields & (1 << 17)) != 0
    }

    pub fn set_outbound(&mut self, outbound: bool) {
        if outbound {
            self.bitfields |= 1 << 17;
        } else {
            self.bitfields &= !(1 << 17);
        }
    }

    pub fn is_ipv6(&self) -> bool {
        (self.bitfields & (1 << 20)) != 0
    }

    pub fn if_idx(&self) -> u32 {
        u32::from_ne_bytes([self.data[0], self.data[1], self.data[2], self.data[3]])
    }

    pub fn sub_if_idx(&self) -> u32 {
        u32::from_ne_bytes([self.data[4], self.data[5], self.data[6], self.data[7]])
    }
}

type FnWinDivertOpen = unsafe extern "system" fn(
    filter: *const i8,
    layer: u32,
    priority: i16,
    flags: u64,
) -> WinDivertHandle;

type FnWinDivertRecv = unsafe extern "system" fn(
    handle: WinDivertHandle,
    packet: *mut u8,
    packet_len: u32,
    recv_len: *mut u32,
    addr: *mut WinDivertAddress,
) -> i32;

type FnWinDivertSend = unsafe extern "system" fn(
    handle: WinDivertHandle,
    packet: *const u8,
    packet_len: u32,
    send_len: *mut u32,
    addr: *const WinDivertAddress,
) -> i32;

type FnWinDivertHelperCalcChecksums = unsafe extern "system" fn(
    packet: *mut u8,
    packet_len: u32,
    addr: *const WinDivertAddress,
    flags: u64,
) -> i32;

type FnWinDivertClose = unsafe extern "system" fn(handle: WinDivertHandle) -> i32;

pub struct WinDivertApi {
    _module: HMODULE,
    fn_open: FnWinDivertOpen,
    fn_recv: FnWinDivertRecv,
    fn_send: FnWinDivertSend,
    fn_calc_checksums: FnWinDivertHelperCalcChecksums,
    fn_close: FnWinDivertClose,
}

impl WinDivertApi {
    pub fn load() -> Result<Self, String> {
        let dll_name: Vec<u16> = "WinDivert.dll\0".encode_utf16().collect();
        let hmodule = unsafe { LoadLibraryW(dll_name.as_ptr()) };
        if hmodule.is_null() {
            return Err("Failed to load WinDivert.dll. Ensure WinDivert.dll and WinDivert64.sys exist in the working directory.".to_string());
        }

        macro_rules! load_proc {
            ($name:ident, $type:ty, $cname:expr) => {
                unsafe {
                    let proc = GetProcAddress(hmodule, $cname.as_ptr());
                    if proc.is_none() {
                        return Err(format!("Failed to find symbol {}", stringify!($name)));
                    }
                    std::mem::transmute::<_, $type>(proc.unwrap())
                }
            };
        }

        let fn_open: FnWinDivertOpen = load_proc!(WinDivertOpen, FnWinDivertOpen, b"WinDivertOpen\0");
        let fn_recv: FnWinDivertRecv = load_proc!(WinDivertRecv, FnWinDivertRecv, b"WinDivertRecv\0");
        let fn_send: FnWinDivertSend = load_proc!(WinDivertSend, FnWinDivertSend, b"WinDivertSend\0");
        let fn_calc_checksums: FnWinDivertHelperCalcChecksums =
            load_proc!(WinDivertHelperCalcChecksums, FnWinDivertHelperCalcChecksums, b"WinDivertHelperCalcChecksums\0");
        let fn_close: FnWinDivertClose = load_proc!(WinDivertClose, FnWinDivertClose, b"WinDivertClose\0");

        Ok(Self {
            _module: hmodule,
            fn_open,
            fn_recv,
            fn_send,
            fn_calc_checksums,
            fn_close,
        })
    }

    pub fn open(&self, filter: &str, layer: u32, priority: i16, flags: u64) -> Result<WinDivertHandle, String> {
        let c_filter = std::ffi::CString::new(filter).map_err(|e| e.to_string())?;
        let handle = unsafe { (self.fn_open)(c_filter.as_ptr(), layer, priority, flags) };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err("WinDivertOpen failed. Administrative privileges required.".to_string());
        }
        Ok(handle)
    }

    pub fn recv(&self, handle: WinDivertHandle, packet: &mut [u8], addr: &mut WinDivertAddress) -> Result<usize, String> {
        let mut recv_len = 0u32;
        let ok = unsafe {
            (self.fn_recv)(
                handle,
                packet.as_mut_ptr(),
                packet.len() as u32,
                &mut recv_len,
                addr as *mut WinDivertAddress,
            )
        };
        if ok == 0 {
            return Err("WinDivertRecv failed".to_string());
        }
        Ok(recv_len as usize)
    }

    pub fn send(&self, handle: WinDivertHandle, packet: &[u8], addr: &WinDivertAddress) -> Result<usize, String> {
        let mut send_len = 0u32;
        let ok = unsafe {
            (self.fn_send)(
                handle,
                packet.as_ptr(),
                packet.len() as u32,
                &mut send_len,
                addr as *const WinDivertAddress,
            )
        };
        if ok == 0 {
            return Err("WinDivertSend failed".to_string());
        }
        Ok(send_len as usize)
    }

    pub fn calc_checksums(&self, packet: &mut [u8], addr: &WinDivertAddress, flags: u64) {
        unsafe {
            (self.fn_calc_checksums)(
                packet.as_mut_ptr(),
                packet.len() as u32,
                addr as *const WinDivertAddress,
                flags,
            );
        }
    }

    pub fn close(&self, handle: WinDivertHandle) {
        if handle != INVALID_HANDLE_VALUE && !handle.is_null() {
            unsafe {
                (self.fn_close)(handle);
            }
        }
    }
}
