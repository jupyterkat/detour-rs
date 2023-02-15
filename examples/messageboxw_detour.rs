#![cfg(all(windows, feature = "nightly"))]
//! A `MessageBoxW` detour example.
//!
//! Ensure the crate is compiled as a 'cdylib' library to allow C interop.
use detour::static_detour;
use std::error::Error;
use std::ffi::{c_int, c_uint, c_void};
use std::mem;

use windows::core::{PCSTR, PCWSTR};
use windows::Win32::Foundation::{BOOL, HINSTANCE, HWND};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;

static_detour! {
  static MessageBoxWHook: unsafe extern "system" fn(HWND, PCWSTR, PCWSTR, c_uint) -> c_int;
}

// A type alias for `MessageBoxW` (makes the transmute easy on the eyes)
type FnMessageBoxW = unsafe extern "system" fn(HWND, PCWSTR, PCWSTR, c_uint) -> c_int;

/// Called when the DLL is attached to the process.
unsafe fn main() -> Result<(), Box<dyn Error>> {
  // Retrieve an absolute address of `MessageBoxW`. This is required for
  // libraries due to the import address table. If `MessageBoxW` would be
  // provided directly as the target, it would only hook this DLL's
  // `MessageBoxW`. Using the method below an absolute address is retrieved
  // instead, detouring all invocations of `MessageBoxW` in the active process.
  let address = get_module_symbol_address(windows::w!("user32.dll"), windows::s!("MessageBoxW"))
    .expect("could not find 'MessageBoxW' address");
  let target: FnMessageBoxW = mem::transmute(address);

  // Initialize AND enable the detour (the 2nd parameter can also be a closure)
  MessageBoxWHook
    .initialize(target, messageboxw_detour)?
    .enable()?;
  Ok(())
}

/// Called whenever `MessageBoxW` is invoked in the process.
fn messageboxw_detour(hwnd: HWND, text: PCWSTR, _caption: PCWSTR, u_type: c_uint) -> c_int {
  // Call the original `MessageBoxW`, but replace the caption
  let replaced_caption = windows::w!("Detoured!");
  unsafe { MessageBoxWHook.call(hwnd, text, replaced_caption, u_type) }
}

/// Returns a module symbol's absolute address.
fn get_module_symbol_address(
  module: PCWSTR,
  symbol: PCSTR,
) -> Option<unsafe extern "system" fn() -> isize> {
  unsafe {
    let handle = GetModuleHandleW(module).unwrap();
    GetProcAddress(handle, symbol)
  }
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "system" fn DllMain(
  _module: HINSTANCE,
  call_reason: u32,
  _reserved: c_void,
) -> BOOL {
  if call_reason == DLL_PROCESS_ATTACH {
    // A console may be useful for printing to 'stdout'
    // windows::Win32::System::Console::AllocConsole();

    // Preferably a thread should be created here instead, since as few
    // operations as possible should be performed within `DllMain`.
    main().is_ok().into()
  } else {
    true.into()
  }
}
