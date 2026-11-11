import Foundation

/// Process-wide lock so only one reader program (the app or mrtd-read) uses the NFC reader at a time;
/// two programs polling the same PC/SC reader interrupt each other's sessions.
public enum ReaderLock {
    private static var fd: Int32 = -1

    /// Returns false if another process already holds the lock. The lock is released when the process exits.
    public static func acquire() -> Bool {
        if fd >= 0 { return true }
        let path = (NSTemporaryDirectory() as NSString).appendingPathComponent("local.passportscanner.reader.lock")
        let f = open(path, O_CREAT | O_RDWR, 0o600)
        guard f >= 0 else { return true } // cannot create the lock file: do not block the user
        if flock(f, LOCK_EX | LOCK_NB) != 0 {
            close(f)
            return false
        }
        fd = f
        return true
    }
}
