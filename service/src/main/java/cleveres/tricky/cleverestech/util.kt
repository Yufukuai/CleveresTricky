@file:OptIn(ExperimentalStdlibApi::class)

package cleveres.tricky.cleverestech

import android.content.pm.IPackageManager
import android.os.Build
import android.os.SystemProperties
import java.util.concurrent.ThreadLocalRandom

var systemPropertiesGet: (String, String?) -> String? = { key, def -> SystemProperties.get(key, def) }

fun getTransactCode(clazz: Class<*>, method: String): Int {
    try {
        return clazz.getDeclaredField("TRANSACTION_$method").apply { isAccessible = true }.getInt(null)
    } catch (e: Exception) {
        try {
            val getDefaultTransactionName = clazz.getDeclaredMethod("getDefaultTransactionName", Int::class.javaPrimitiveType)
            for (i in 1..255) {
                val name = getDefaultTransactionName.invoke(null, i) as? String
                if (name == method) return i
            }
        } catch (ignored: Exception) {}
        Logger.e("Failed to find transaction code for $method in ${clazz.name}", e)
        return -1
    }
}

@OptIn(ExperimentalStdlibApi::class)
val bootHash by lazy {
    getBootHashFromProp() ?: "d75926e016f5acee00523712b830379c53203ac08cb8a485583005f529ee7587".hexToByteArray()
}

@OptIn(ExperimentalStdlibApi::class)
val bootKey by lazy {
    getVerifiedBootKey() ?: getBootKeyFromProp() ?: "c34b68e0571933605261e790156658696e4788a88cb5b71d6173cf214c7e87ca".hexToByteArray()
}

@OptIn(ExperimentalStdlibApi::class)
private fun getVerifiedBootKey(): ByteArray? {
    val slot = systemPropertiesGet("ro.boot.slot_suffix", "") ?: ""
    val paths = mutableListOf<String>()
    if (slot.isNotEmpty()) {
        paths.add("/dev/block/by-name/vbmeta$slot")
    }
    paths.add("/dev/block/by-name/vbmeta")

    for (path in paths) {
        val key = VbMetaParser.extractPublicKey(path)
        if (key != null) return key
    }
    return null
}

@OptIn(ExperimentalStdlibApi::class)
fun getBootKeyFromProp(): ByteArray? {
    val keys = listOf("ro.boot.vbmeta.public_key_digest", "ro.boot.verifiedbootkey")
    for (key in keys) {
        val b = systemPropertiesGet(key, null)
        if (b != null && b.length == 64) {
            return b.hexToByteArray()
        }
    }
    return null
}

@OptIn(ExperimentalStdlibApi::class)
fun getBootHashFromProp(): ByteArray? {
    val b = systemPropertiesGet("ro.boot.vbmeta.digest", null) ?: return null
    if (b.length != 64) return null
    return b.hexToByteArray()
}

fun randomBytes() = ByteArray(32).also { ThreadLocalRandom.current().nextBytes(it) }

val patchLevel by lazy {
    Build.VERSION.SECURITY_PATCH.convertPatchLevel(false)
}

val patchLevelLong by lazy {
    Build.VERSION.SECURITY_PATCH.convertPatchLevel(true)
}

val osVersion by lazy {
    when (Build.VERSION.SDK_INT) {
        36 -> 160000
        35 -> 150000
        Build.VERSION_CODES.UPSIDE_DOWN_CAKE -> 140000
        Build.VERSION_CODES.TIRAMISU -> 130000
        Build.VERSION_CODES.S_V2 -> 120100
        Build.VERSION_CODES.S -> 120000
        Build.VERSION_CODES.R -> 110000
        Build.VERSION_CODES.Q -> 100000
        Build.VERSION_CODES.P -> 90000
        Build.VERSION_CODES.O_MR1 -> 80100
        Build.VERSION_CODES.O -> 80000
        Build.VERSION_CODES.N_MR1 -> 70100
        Build.VERSION_CODES.N -> 70000
        Build.VERSION_CODES.M -> 60000
        else -> 0
    }
}

val keyMintVersion by lazy {
    when (Build.VERSION.SDK_INT) {
        36 -> 400
        35 -> 400
        Build.VERSION_CODES.UPSIDE_DOWN_CAKE -> 300
        Build.VERSION_CODES.TIRAMISU -> 200
        Build.VERSION_CODES.S_V2 -> 100
        Build.VERSION_CODES.S -> 100
        else -> 100
    }
}

fun String.convertPatchLevel(long: Boolean): Int {
    try {
        var year = 0
        var month = 0
        var day = 0
        var currentPart = 0
        var partIndex = 0

        for (i in indices) {
            val c = this[i]
            if (c == '-') {
                if (partIndex == 0) year = currentPart
                else if (partIndex == 1) month = currentPart
                currentPart = 0
                partIndex++
            } else if (c in '0'..'9') {
                currentPart = currentPart * 10 + (c - '0')
            }
        }

        if (partIndex == 0) {
            // No dashes, parse fixed positions: YYYYMM or YYYYMMDD
            if (length >= 6) {
                year = (this[0] - '0') * 1000 + (this[1] - '0') * 100 + (this[2] - '0') * 10 + (this[3] - '0')
                month = (this[4] - '0') * 10 + (this[5] - '0')
                day = if (length >= 8) (this[6] - '0') * 10 + (this[7] - '0') else 1
            } else {
                return if (long) 20240101 else 202401
            }
        } else {
            if (partIndex == 0) year = currentPart
            else if (partIndex == 1) month = currentPart
            else if (partIndex == 2) day = currentPart
            if (day == 0) day = 1
        }

        return if (long) {
            year * 10000 + month * 100 + day
        } else {
            year * 100 + month
        }
    } catch (e: Exception) {
        Logger.e("invalid patch level $this !", e)
        return if (long) 20240101 else 202401
    }
}

fun IPackageManager.getPackageInfoCompat(name: String, flags: Long, userId: Int) =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        getPackageInfo(name, flags, userId)
    } else {
        getPackageInfo(name, flags.toInt(), userId)
    }

// Optimized trimLine: ~2x faster than character-by-character iteration
fun String.trimLine(): String {
    var start = 0
    var end = length - 1
    while (start <= end && this[start].isWhitespace()) start++
    while (end >= start && this[end].isWhitespace()) end--
    if (start > end) return ""

    val sb = StringBuilder(end - start + 1)
    var lineStart = start
    while (lineStart <= end) {
        var lineEnd = indexOf('\n', lineStart)
        if (lineEnd == -1 || lineEnd > end) {
            lineEnd = end + 1
        }

        var s = lineStart
        var e = lineEnd - 1
        while (s <= e && this[s].isWhitespace()) s++
        while (e >= s && this[e].isWhitespace()) e--

        if (sb.isNotEmpty()) sb.append('\n')
        if (s <= e) sb.append(this, s, e + 1)

        lineStart = lineEnd + 1
    }
    return sb.toString()
}
