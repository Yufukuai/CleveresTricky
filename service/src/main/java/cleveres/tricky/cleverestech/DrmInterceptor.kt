package cleveres.tricky.cleverestech

import android.os.IBinder
import android.os.Parcel
import android.os.ServiceManager
import cleveres.tricky.cleverestech.binder.BinderInterceptor
import java.io.File
import java.security.SecureRandom
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.Dispatchers

/**
 * Intercepts DRM HAL Binder transactions to spoof Widevine security level and device ID.
 *
 * Supports both AIDL (Android 13+) and HIDL (Android 12) DRM service variants.
 * Handles two transaction types:
 *   - getPropertyString (17): Spoofs "securityLevel" from L3/L2 to L1
 *   - getPropertyByteArray (18): Spoofs "deviceUniqueId" with random 32 bytes
 *
 * The interceptor uses cached state to avoid per-transaction file I/O
 * and reuses a thread-local SecureRandom instance for performance.
 */
object DrmInterceptor : BinderInterceptor() {

    @Volatile private var drmBinder: IBinder? = null
    @Volatile private var triedCount = 0
    @Volatile private var injected = false
    @Volatile private var isInjecting = false

    // Cached state to avoid file I/O on every transaction
    @Volatile private var cachedRandomDrmOnBoot = false
    @Volatile private var cachedDrmConfigTime = 0L

    private const val TRANSACTION_GET_PROPERTY_STRING = 17
    private const val TRANSACTION_GET_PROPERTY_BYTE_ARRAY = 18

    // Cache refresh interval (60 seconds)
    private const val CONFIG_CACHE_TTL_MS = 60_000L

    // Thread-local SecureRandom to avoid contention and allocation per call
    private val secureRandom: ThreadLocal<SecureRandom> =
        ThreadLocal.withInitial { SecureRandom() }
    private val threadSecureRandom: SecureRandom
        get() = requireNotNull(secureRandom.get()) { "ThreadLocal SecureRandom must not be null" }

    // All known DRM HAL service names (AIDL + HIDL variants across Android 12-15+)
    private val DRM_SERVICE_NAMES = listOf(
        // AIDL (Android 13+)
        "android.hardware.drm.IDrmFactory/widevine",
        "android.hardware.drm.IDrmFactory/clearkey",
        // Legacy AIDL
        "drm.IDrmFactory/widevine",
        // HIDL (Android 12)
        "android.hardware.drm@1.4::ICryptoFactory/widevine",
        "android.hardware.drm@1.3::ICryptoFactory/widevine",
        // Media DRM server
        "media.drm"
    )

    // All known DRM process names to find PID for injection
    private val DRM_PROCESS_NAMES = setOf(
        // AIDL service (Android 13+)
        "android.hardware.drm-service.widevine",
        "android.hardware.drm-service.clearkey",
        // HIDL (Android 12-13)
        "android.hardware.drm@1.4-service.widevine",
        "android.hardware.drm@1.3-service.widevine",
        "android.hardware.drm@1.2-service.widevine",
        // Legacy media DRM
        "mediadrmserver",
        // Samsung/vendor variants
        "vendor.samsung.hardware.drm-service.widevine"
    )

    /**
     * Refreshes cached DRM config from filesystem.
     * Called on a lazy schedule to minimize I/O on the hot path.
     */
    private fun refreshConfigCache() {
        val now = System.currentTimeMillis()
        if (now - cachedDrmConfigTime < CONFIG_CACHE_TTL_MS) return
        cachedRandomDrmOnBoot = File("/data/adb/cleverestricky/random_drm_on_boot").exists()
        cachedDrmConfigTime = now
        Logger.d("DRM: Config cache refreshed (randomDrmOnBoot=$cachedRandomDrmOnBoot)")
    }

    override fun onPostTransact(
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
        reply: Parcel?,
        resultCode: Int
    ): Result {
        if (reply == null) return Skip
        if (!Config.isDrmFixEnabled()) return Skip

        // Lazy refresh config cache to avoid per-transaction file I/O
        refreshConfigCache()

        return when (code) {
            TRANSACTION_GET_PROPERTY_STRING -> handleGetPropertyString(data, reply, callingUid)
            TRANSACTION_GET_PROPERTY_BYTE_ARRAY -> handleGetPropertyByteArray(data, reply, callingUid)
            else -> Skip
        }
    }

    private fun handleGetPropertyString(data: Parcel, reply: Parcel, callingUid: Int): Result {
        val propertyName = readTrackedPropertyName(data)
        if (propertyName != DrmOverrideLogic.SECURITY_LEVEL_PROPERTY) return Skip

        val pos = reply.dataPosition()
        // Optimization: Replace runCatching with try-catch to avoid Result object allocation in hot path
        try {
            reply.readException()
        } catch (e: Exception) {
            reply.setDataPosition(pos)
            return Skip
        }
        val originalValue = reply.readString()
        if (originalValue == null) {
            reply.setDataPosition(pos)
            return Skip
        }

        // Spoof Widevine security level: L3/L2 -> L1 (or configured level)
        if (originalValue == "L3" || originalValue == "L2") {
            val targetLevel = Config.getBuildVar("ro.com.google.widevine.level") ?: "1"
            val spoofedLevel = "L$targetLevel"
            Logger.i("DRM: Spoofing securityLevel $originalValue -> $spoofedLevel for uid=$callingUid")
            val p = Parcel.obtain()
            try {
                p.writeNoException()
                p.writeString(spoofedLevel)
                return OverrideReply(0, p)
            } catch (e: Exception) {
                p.recycle()
                Logger.e("DRM: Failed to write spoofed security level", e)
                return Skip
            }
        }

        return Skip
    }

    private fun handleGetPropertyByteArray(data: Parcel, reply: Parcel, callingUid: Int): Result {
        val propertyName = readTrackedPropertyName(data)
        if (propertyName != DrmOverrideLogic.DEVICE_UNIQUE_ID_PROPERTY) return Skip
        if (!DrmOverrideLogic.shouldSpoofDeviceUniqueId(propertyName, cachedRandomDrmOnBoot)) return Skip
        val pos = reply.dataPosition()
        // Optimization: Replace runCatching with try-catch to avoid Result object allocation in hot path
        try {
            reply.readException()
        } catch (e: Exception) {
            reply.setDataPosition(pos)
            return Skip
        }

        val spoofedId = ByteArray(32)
        threadSecureRandom.nextBytes(spoofedId)
        Logger.i("DRM: Spoofing deviceUniqueId (32 bytes) for uid=$callingUid")
        val p = Parcel.obtain()
        try {
            p.writeNoException()
            p.writeByteArray(spoofedId)
            return OverrideReply(0, p)
        } catch (e: Exception) {
            p.recycle()
            Logger.e("DRM: Failed to write spoofed device ID", e)
            return Skip
        }
    }

    private fun readTrackedPropertyName(data: Parcel): String? {
        val pos = data.dataPosition()
        return try {
            DrmOverrideLogic.findTrackedPropertyName(listOf(data.readString(), data.readString()))
        } catch (_: Exception) {
            null
        } finally {
            data.setDataPosition(pos)
        }
    }

    private fun isRandomDrmOnBootEnabled(): Boolean {
        return File(Config.getConfigRoot(), "random_drm_on_boot").exists()
    }

    @Volatile private var cachedDrmPid: Int? = null

    private fun findDrmServicePid(): Int? {
        val cachedPid = cachedDrmPid
        if (cachedPid != null) {
            val buf = ByteArray(1024)
            try {
                val stream = java.io.FileInputStream("/proc/$cachedPid/cmdline")
                val length = try {
                    stream.read(buf)
                } finally {
                    stream.close()
                }
                if (length > 0) {
                    var end = 0
                    var start = 0
                    while (end < length && buf[end] != 0.toByte()) {
                        if (buf[end] == 47.toByte()) start = end + 1 // Track last slash '/'
                        end++
                    }
                    val argv0 = String(buf, start, end - start)
                    if (DRM_PROCESS_NAMES.contains(argv0)) {
                        return cachedPid
                    }
                }
            } catch (e: Exception) {
                // Ignore file read errors
            }
            cachedDrmPid = null
        }

        val proc = File("/proc")
        if (!proc.exists() || !proc.isDirectory) return null

        val pids = proc.list() ?: return null

        val buf = ByteArray(1024)
        for (i in 0 until pids.size) {
            val pidStr = pids[i]
            if (!(pidStr.isNotEmpty() && pidStr[0] in '1'..'9')) continue
            try {
                val stream = java.io.FileInputStream("/proc/$pidStr/cmdline")
                val length = try {
                    stream.read(buf)
                } finally {
                    stream.close()
                }
                if (length > 0) {
                    var end = 0
                    var start = 0
                    while (end < length && buf[end] != 0.toByte()) {
                        if (buf[end] == 47.toByte()) start = end + 1 // Track last slash '/'
                        end++
                    }
                    val argv0 = String(buf, start, end - start)
                    if (DRM_PROCESS_NAMES.contains(argv0)) {
                        val parsedPid = pidStr.toInt()
                        Logger.d("DRM: Found DRM process '$argv0' at PID $parsedPid")
                        cachedDrmPid = parsedPid
                        return parsedPid
                    }
                }
            } catch (e: Exception) {
                // Ignore file read errors
            }
        }
        return null
    }

    private fun findDrmService(): IBinder? {
        for (name in DRM_SERVICE_NAMES) {
            val b = kotlin.runCatching { ServiceManager.getService(name) }.getOrNull()
            if (b != null) {
                Logger.d("DRM: Found service via '$name'")
                return b
            }
        }
        return null
    }

    fun tryRunDrmInterceptor(): Boolean {
        if (!Config.isDrmFixEnabled()) return false

        Logger.i("DRM: Attempting registration (attempt=$triedCount, injected=$injected)")

        val b = findDrmService()
        if (b == null) {
            Logger.d("DRM: Service not found, will retry")
            triedCount += 1
            return false
        }

        val bd = getBinderBackdoor(b)
        if (bd == null) {
            if (triedCount >= 3) {
                Logger.e("DRM: Exhausted $triedCount injection attempts, giving up")
                return false
            }

            if (!injected && !isInjecting) {
                isInjecting = true
                Logger.i("DRM: Backdoor not found, attempting injection into DRM process...")
                val pid = findDrmServicePid()
                if (pid == null) {
                    Logger.e("DRM: Cannot find DRM service PID in /proc")
                    triedCount += 1
                    return false
                }

                val modulePath = "/data/adb/modules/cleverestricky"
                Logger.d("DRM: Injecting PID=$pid with $modulePath/libcleverestricky.so")
                Thread {
                    try {
                        val abi = android.os.Build.SUPPORTED_ABIS.firstOrNull() ?: "arm64-v8a"
                        val p = Runtime.getRuntime().exec(
                            arrayOf(
                                "$modulePath/lib/$abi/inject",
                                pid.toString(),
                                "$modulePath/libcleverestricky.so",
                                "entry"
                            )
                        )
                        try {
                            p.inputStream.readBytes()
                        } catch (_: Exception) {}
                        finally {
                            try { p.errorStream.readBytes() } catch (_: Exception) {}
                        }
                        val exitCode = p.waitFor()
                        if (exitCode != 0) {
                            Logger.e("DRM: Injection failed (exit=$exitCode)")
                        } else {
                            Logger.i("DRM: Injection succeeded for PID=$pid")
                            injected = true
                        }
                    } finally {
                        isInjecting = false
                    }
                }.start()
            }
            triedCount += 1
            return false
        }

        drmBinder = b
        Logger.i("DRM: Binder interceptor registered successfully!")
        registerBinderInterceptor(bd, b, this)
        b.linkToDeath({
            Logger.e("DRM: Service died — resetting state for re-injection")
            injected = false
            triedCount = 0
            drmBinder = null
            cachedDrmConfigTime = 0 // Force config refresh on next transaction
        }, 0)

        // Force initial config load
        refreshConfigCache()

        return true
    }
}
