//! Best-effort memory locking for the vault master key.
//!
//! This is deliberately narrow in scope. Locking is only meaningful for a buffer whose
//! address is stable for its whole lifetime: `mlock`/`VirtualLock` lock a page range, and if
//! the underlying value later moves (as any ordinary stack-allocated Rust value can, on
//! return or reassignment) the lock is left behind on the old, now-unrelated page while the
//! new location remains unlocked. [`VaultKey`](crate::VaultKey) is heap-allocated
//! specifically so that locking it once, right after allocation, stays valid for the value's
//! whole lifetime. Subkeys derived from it (see [`crate::SubkeyPurpose`]) are short-lived,
//! stack-allocated, per-use buffers; locking those would require boxing every derived subkey
//! for comparatively little benefit, so they are intentionally left unlocked. That trade-off
//! is a scoping decision, not an oversight - see `docs/implementation-plan.md` Phase 1.
//!
//! Locking is best-effort everywhere: failures (missing privilege, exceeded `RLIMIT_MEMLOCK`,
//! locked-pages quota, etc.) are ignored rather than treated as fatal, per the project's
//! position that memory locking is used "where practical without pretending this defeats a
//! hostile OS". A locked page can still be captured by a sufficiently privileged attacker
//! (root, a kernel-level acquisition tool, a hypervisor); this only removes the ordinary
//! swap/hibernation-file exposure path.

/// Lock the page(s) containing `[ptr, ptr + len)` in physical memory, best-effort.
pub(crate) fn lock(ptr: *const u8, len: usize) {
    imp::lock(ptr, len);
}

/// Undo a previous [`lock`] call for the same range, best-effort.
pub(crate) fn unlock(ptr: *const u8, len: usize) {
    imp::unlock(ptr, len);
}

#[cfg(unix)]
mod imp {
    pub(super) fn lock(ptr: *const u8, len: usize) {
        // SAFETY: `mlock` only reads the address/length pair to select which pages to pin; it
        // does not dereference or retain the pointer, so this is safe for any valid
        // `(ptr, len)` describing memory the caller owns, even after `mlock` returns.
        unsafe {
            let _ = libc::mlock(ptr.cast(), len);
        }
    }

    pub(super) fn unlock(ptr: *const u8, len: usize) {
        // SAFETY: see `lock` above; `munlock` has the same contract.
        unsafe {
            let _ = libc::munlock(ptr.cast(), len);
        }
    }
}

#[cfg(windows)]
mod imp {
    use windows_sys::Win32::System::Memory::{VirtualLock, VirtualUnlock};

    pub(super) fn lock(ptr: *const u8, len: usize) {
        // SAFETY: `VirtualLock` only reads the address/length pair to select which pages to
        // pin; it does not dereference or retain the pointer beyond the call.
        unsafe {
            let _ = VirtualLock(ptr as *mut core::ffi::c_void, len);
        }
    }

    pub(super) fn unlock(ptr: *const u8, len: usize) {
        // SAFETY: see `lock` above; `VirtualUnlock` has the same contract.
        unsafe {
            let _ = VirtualUnlock(ptr as *mut core::ffi::c_void, len);
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    pub(super) fn lock(_ptr: *const u8, _len: usize) {}
    pub(super) fn unlock(_ptr: *const u8, _len: usize) {}
}
