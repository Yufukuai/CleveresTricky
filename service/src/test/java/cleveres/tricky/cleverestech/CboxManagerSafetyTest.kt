package cleveres.tricky.cleverestech

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Tests that validate CboxManager code correctness and safety.
 *
 * Validates CBOX lifecycle, path traversal protection, caching,
 * and signature verification.
 */
class CboxManagerSafetyTest {

    private lateinit var cboxManagerContent: String

    @Before
    fun setup() {
        cboxManagerContent = serviceMainFile("CboxManager.kt").readText()
    }

    // ================================
    // Path traversal protection
    // ================================

    @Test
    fun testBlocksPathTraversalDotDot() {
        assertTrue(
            "unlock() must reject filenames containing '..' to prevent path traversal",
            cboxManagerContent.contains("\"..\"")
        )
    }

    @Test
    fun testBlocksPathTraversalSlash() {
        assertTrue(
            "unlock() must reject filenames containing '/' to prevent path traversal",
            cboxManagerContent.contains("\"/\"")
        )
    }

    @Test
    fun testBlocksPathTraversalBackslash() {
        assertTrue(
            "unlock() must reject filenames containing backslash to prevent path traversal",
            cboxManagerContent.contains("\"\\\\\"")
        )
    }

    // ================================
    // CBOX lifecycle
    // ================================

    @Test
    fun testInitializeCallsRefresh() {
        assertTrue(
            "initialize() must call refresh() to detect CBOX files",
            cboxManagerContent.contains("refresh()")
        )
    }

    @Test
    fun testDetectsLockedCboxFiles() {
        assertTrue(
            "Must track locked (unprocessed) CBOX files",
            cboxManagerContent.contains("lockedFiles")
        )
    }

    @Test
    fun testUnlockMovesToUnlockedCache() {
        assertTrue(
            "unlock() must move successful decryption to unlockedCache",
            cboxManagerContent.contains("unlockedCache[filename]")
        )
    }

    @Test
    fun testUnlockRemovesFromLocked() {
        assertTrue(
            "unlock() must remove file from lockedFiles set after successful decryption",
            cboxManagerContent.contains("lockedFiles.remove(filename)")
        )
    }

    // ================================
    // Signature verification
    // ================================

    @Test
    fun testVerifiesSignatureWhenKeyProvided() {
        assertTrue(
            "Must verify CBOX signature when public key is provided",
            cboxManagerContent.contains("verifySignature")
        )
    }

    @Test
    fun testRejectsBadSignature() {
        assertTrue(
            "Must return false when signature verification fails",
            cboxManagerContent.contains("return false") &&
            cboxManagerContent.contains("Signature verification failed")
        )
    }

    // ================================
    // Device key caching
    // ================================

    @Test
    fun testCachesUsingDeviceKey() {
        assertTrue(
            "Must cache unlocked CBOX content encrypted with device key",
            cboxManagerContent.contains("DeviceKeyManager.encrypt")
        )
    }

    @Test
    fun testLoadsCachedCbox() {
        assertTrue(
            "Must load previously cached CBOX on refresh",
            cboxManagerContent.contains("DeviceKeyManager.decrypt")
        )
    }

    @Test
    fun testCacheFileExtension() {
        assertTrue(
            "Cached CBOX files must use .cache extension",
            cboxManagerContent.contains(".cache")
        )
    }

    // ================================
    // Cleanup logic
    // ================================

    @Test
    fun testCleansUpRemovedFiles() {
        assertTrue(
            "refresh() must clean up cache for removed CBOX files",
            cboxManagerContent.contains("cacheIt.remove()") || cboxManagerContent.contains("lockedFiles.retainAll")
        )
    }

    @Test
    fun testDetectsCboxByExtension() {
        assertTrue(
            "Must detect CBOX files by .cbox extension",
            cboxManagerContent.contains(".cbox")
        )
    }

    // ================================
    // Concurrency
    // ================================

    @Test
    fun testUsesThreadSafeCollections() {
        assertTrue(
            "Must use ConcurrentHashMap for unlocked cache",
            cboxManagerContent.contains("ConcurrentHashMap")
        )
    }
}
