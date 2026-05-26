package cleveres.tricky.cleverestech.util

import cleveres.tricky.cleverestech.Logger
import cleveres.tricky.cleverestech.keystore.CertHack
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.concurrent.Executors

object KeyboxVerifier {

    data class Result(
        val file: File,
        val filename: String,
        val status: Status,
        val details: String
    )

    enum class Status {
        VALID, REVOKED, INVALID, ERROR
    }

    private var CRL_URL = "https://android.googleapis.com/attestation/status"
    private val HASH_LENGTHS = listOf(32, 40, 64)
    private val ZEROS = "0".repeat(64)

    @androidx.annotation.VisibleForTesting
    fun setCrlUrlForTesting(url: String) {
        CRL_URL = url
    }

    private var cachedCrl: Set<String>? = null
    private var cachedEtag: String? = null
    private var lastFetchTime: Long = 0
    private const val CACHE_TTL = 24 * 60 * 60 * 1000L // 24 hours
    private val cacheLock = java.util.concurrent.locks.ReentrantLock()

    private fun isHex(str: String): Boolean {
        if (str.isEmpty()) return false
        for (i in 0 until str.length) {
            val c = str[i]
            if (!(c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F')) {
                return false
            }
        }
        return true
    }

    @JvmStatic
    @JvmOverloads
    fun verify(configDir: File, crlFetcher: () -> Set<String>? = { fetchCrl() }): List<Result> {
        val results = ArrayList<Result>()
        val revokedSerials = crlFetcher()

        if (revokedSerials == null) {
            return listOf(Result(File(""), "Global", Status.ERROR, "Failed to fetch CRL from Google"))
        }

        if (!configDir.exists() || !configDir.isDirectory) {
             return listOf(Result(File(""), "Global", Status.ERROR, "Config directory not found"))
        }

        // Check legacy keybox.xml
        val legacyFile = File(configDir, "keybox.xml")
        if (legacyFile.exists()) {
            results.add(checkFile(legacyFile, revokedSerials))
        }

        // Check jukebox files
        val keyboxDir = File(configDir, "keyboxes")
        if (keyboxDir.exists() && keyboxDir.isDirectory) {
            val files = keyboxDir.listFiles { _, name -> name.endsWith(".xml") } ?: emptyArray()
            for (file in files) {
                results.add(checkFile(file, revokedSerials))
            }
        }

        return results
    }

    @JvmStatic
    fun fetchCrl(): Set<String>? {
        val now = System.currentTimeMillis()
        cacheLock.lock()
        try {
            if (cachedCrl != null && (now - lastFetchTime) < CACHE_TTL) {
                return cachedCrl
            }
        } finally {
            cacheLock.unlock()
        }

        return try {
            val url = URL(CRL_URL)
            val conn = url.openConnection() as HttpURLConnection
            conn.connectTimeout = 10000
            conn.readTimeout = 10000
            conn.requestMethod = "GET"

            cacheLock.lock()
            try {
                cachedEtag?.let {
                    conn.setRequestProperty("If-None-Match", it)
                }
            } finally {
                cacheLock.unlock()
            }

            val responseCode = conn.responseCode
            if (responseCode == 304) {
                cacheLock.lock()
                try {
                    lastFetchTime = now
                    return cachedCrl
                } finally {
                    cacheLock.unlock()
                }
            }

            if (responseCode != 200) {
                Logger.e("CRL Fetch Failed: $responseCode")
                // Return cached if available even if expired, as fallback
                cacheLock.lock()
                try {
                    return cachedCrl
                } finally {
                    cacheLock.unlock()
                }
            }

            val etag = conn.getHeaderField("ETag")

            // Use streaming parser to prevent OOM on large CRL files
            val newCrl = conn.inputStream.bufferedReader().use { reader ->
                parseCrl(reader)
            }

            cacheLock.lock()
            try {
                cachedCrl = newCrl
                cachedEtag = etag
                lastFetchTime = now
            } finally {
                cacheLock.unlock()
            }
            newCrl
        } catch (e: Exception) {
            Logger.e("Failed to fetch CRL", e)
            cacheLock.lock()
            try {
                cachedCrl // Fallback to cache on error
            } finally {
                cacheLock.unlock()
            }
        }
    }

    @JvmStatic
    fun parseCrl(jsonStr: String): Set<String> {
        return parseCrl(java.io.StringReader(jsonStr))
    }

    @JvmStatic
    fun countRevokedKeys(): Int {
        return fetchCrl()?.size ?: -1
    }

    @JvmStatic
    fun countCrlEntries(reader: java.io.Reader): Int {
        var count = 0
        val jsonReader = android.util.JsonReader(reader)
        var entriesFound = false
        try {
            jsonReader.beginObject()
            while (jsonReader.hasNext()) {
                val name = jsonReader.nextName()
                if (name == "entries") {
                    entriesFound = true
                    jsonReader.beginObject()
                    while (jsonReader.hasNext()) {
                        jsonReader.nextName() // Skip key
                        jsonReader.skipValue() // Skip value
                        count++
                    }
                    jsonReader.endObject()
                } else {
                    jsonReader.skipValue()
                }
            }
            jsonReader.endObject()
        } catch (e: Exception) {
            Logger.e("Failed to count CRL JSON entries", e)
            return -1
        } finally {
            try { jsonReader.close() } catch (e: Exception) {}
        }
        return if (entriesFound) count else -1
    }

    @JvmStatic
    fun parseCrl(reader: java.io.Reader): Set<String> {
        val set = HashSet<String>()
        val jsonReader = android.util.JsonReader(reader)
        var entriesFound = false
        try {
            jsonReader.beginObject()
            while (jsonReader.hasNext()) {
                val name = jsonReader.nextName()
                if (name == "entries") {
                    entriesFound = true
                    jsonReader.beginObject()
                    while (jsonReader.hasNext()) {
                        val decStr = jsonReader.nextName()
                        jsonReader.skipValue() // Value is "REVOKED"
                        processEntry(decStr, set)
                    }
                    jsonReader.endObject()
                } else {
                    jsonReader.skipValue()
                }
            }
            jsonReader.endObject()

            if (!entriesFound) {
                throw IOException("Invalid CRL: 'entries' object missing")
            }
        } catch (e: Exception) {
            Logger.e("Failed to parse CRL JSON", e)
            throw IOException("Failed to parse CRL", e)
        } finally {
            try { jsonReader.close() } catch (e: Exception) {}
        }

        if (!entriesFound) {
            throw IOException("CRL missing 'entries' field")
        }
        return set
    }

    private fun processEntry(decStr: String, set: HashSet<String>) {
        var added = false

        // Try treating as Decimal first (Spec compliant)
        var isDecimal = true
        if (decStr.length > 1 && decStr.startsWith("0")) {
            isDecimal = false
        } else {
            for (i in 0 until decStr.length) {
                if (i == 0 && decStr[i] == '-' && decStr.length > 1) {
                    continue
                }
                if (!Character.isDigit(decStr[i])) {
                    isDecimal = false
                    break
                }
            }
        }

        if (isDecimal && decStr.isNotEmpty()) {
            try {
                val hexStr = java.math.BigInteger(decStr).toString(16)
                set.add(hexStr)

                // BigInteger removes leading zeros. Hashes are fixed length (MD5=32, SHA1=40, SHA256=64).
                // If this decimal is actually a hash, we might need the padded version.
                val hexLen = hexStr.length
                for (targetLen in HASH_LENGTHS) {
                    if (hexLen < targetLen) {
                        set.add(ZEROS.substring(0, targetLen - hexLen) + hexStr)
                    }
                }

                added = true
            } catch (e: Exception) {
                // Should not happen, but safe fallback
            }
        }

        // Ambiguity handling
        // If the string matches a hash length and format, we include it as a raw hex string
        // regardless of whether it was also parsed as a decimal serial number.
        // This prevents "Fail Open" scenarios where a hash composed entirely of digits
        // would otherwise be ignored as a hash.
        if (decStr.length == 32 || decStr.length == 40 || decStr.length == 64) {
            if (isHex(decStr)) {
                set.add(decStr.lowercase())
            }
        }

        if (!added) {
            // Try treating as Hex (literal) as fallback
            if (isHex(decStr)) {
                try {
                    val hexStr = java.math.BigInteger(decStr, 16).toString(16)
                    set.add(hexStr)
                    added = true
                } catch (e: Exception) {
                }
            }
        }

        if (!added) {
            Logger.e("Failed to parse CRL entry key: $decStr")
        }
    }

    private fun checkFile(file: File, revokedSerials: Set<String>): Result {
        return try {
            val keyboxes = file.bufferedReader().use { reader ->
                CertHack.parseKeyboxXml(reader)
            }

            if (keyboxes.isEmpty()) {
                return Result(file, file.name, Status.INVALID, "No valid keyboxes found or parse error")
            }

            for (kb in keyboxes) {
                val status = verifyKeybox(kb, revokedSerials)
                if (status == Status.REVOKED) {
                    val chain = kb.certificates()
                    val sn = if (chain.isNotEmpty() && chain[0] is X509Certificate) {
                         (chain[0] as X509Certificate).serialNumber.toString(16).lowercase()
                    } else "unknown"
                    return Result(file, file.name, Status.REVOKED, "Certificate with SN $sn is revoked")
                } else if (status == Status.INVALID) {
                    return Result(file, file.name, Status.INVALID, "Keybox structure is invalid")
                }
            }

            Result(file, file.name, Status.VALID, "Active (${keyboxes.size} keys)")
        } catch (e: Exception) {
            Result(file, file.name, Status.ERROR, "Error: ${e.javaClass.simpleName}")
        }
    }

    @JvmStatic
    fun verifyKeybox(kb: CertHack.KeyBox, revokedSerials: Set<String>): Status {
        val chain = kb.certificates()
        if (chain.isEmpty()) return Status.INVALID

        for (cert in chain) {
            if (cert is X509Certificate) {
                if (isRevoked(cert, revokedSerials)) {
                    return Status.REVOKED
                }
            }
        }
        return Status.VALID
    }

    @JvmStatic
    fun isRevoked(cert: X509Certificate, revokedSerials: Set<String>): Boolean {
        // 1. Serial Number (Hex)
        val sn = cert.serialNumber.toString(16).lowercase()
        if (revokedSerials.contains(sn)) return true

        // 2. Key ID Checks (Hash of Public Key)
        val publicKeyEncoded = cert.publicKey.encoded

        // SHA-1 (40 chars)
        if (checkHash(publicKeyEncoded, "SHA-1", revokedSerials)) return true

        // SHA-256 (64 chars)
        if (checkHash(publicKeyEncoded, "SHA-256", revokedSerials)) return true

        // MD5 (32 chars)
        if (checkHash(publicKeyEncoded, "MD5", revokedSerials)) return true

        return false
    }

    @OptIn(ExperimentalStdlibApi::class)
    private val hexFormat = HexFormat { upperCase = false }

    private val digestCache = object : ThreadLocal<HashMap<String, MessageDigest>>() {
        override fun initialValue(): HashMap<String, MessageDigest> {
            return HashMap()
        }
    }

    @OptIn(ExperimentalStdlibApi::class)
    private fun checkHash(data: ByteArray, algorithm: String, set: Set<String>): Boolean {
        try {
            val cache = digestCache.get()!!
            var md = cache[algorithm]
            if (md == null) {
                md = MessageDigest.getInstance(algorithm)
                cache[algorithm] = md
            } else {
                md.reset()
            }
            val digest = md.digest(data)
            // Convert to Hex String (Zero Padded)
            val hex = digest.toHexString(hexFormat)
            return set.contains(hex)
        } catch (e: Exception) {
            return false
        }
    }
}
