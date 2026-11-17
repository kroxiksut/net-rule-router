fn main() {
    #[cfg(windows)]
    let _ = nrr_platform_windows::dll_search::restrict_dll_search();
    let _ = nrr_browser_native_host::run_stdio();
}
