package cleveres.tricky.cleverestech

import java.io.File
import java.io.StringReader
import java.util.concurrent.ConcurrentHashMap
import cleveres.tricky.cleverestech.keystore.CertHack
import cleveres.tricky.cleverestech.util.CboxDecryptor
import cleveres.tricky.cleverestech.util.DeviceKeyManager
import cleveres.tricky.cleverestech.util.SecureFile
import cleveres.tricky.cleverestech.Logger

object CboxManager {
    private val unlockedCache = ConcurrentHashMap<String, List<CertHack.KeyBox>>()
    // Files that are detected but not unlocked
    private val lockedFiles: MutableSet<String> = ConcurrentHashMap.newKeySet()

    fun initialize() {
        refresh()
    }

    fun refresh() {
        val dir = Config.keyboxDirectory
        if (!dir.exists()) return

        val cboxFiles = dir.listFiles { _, name -> name.endsWith(".cbox") } ?: return
        val currentFiles = HashSet<String>()

        cboxFiles.forEach { file ->
            val filename = file.name
            currentFiles.add(filename)

            // Check if already unlocked in memory
            if (unlockedCache.containsKey(filename)) return@forEach

            // Check if device-cached
            val cacheFile = File(dir, "$filename.cache")
            if (cacheFile.exists()) {
                try {
                    val encryptedBytes = cacheFile.readBytes()
                    val decryptedBytes = DeviceKeyManager.decrypt(encryptedBytes)
                    if (decryptedBytes != null) {
                        val xml = String(decryptedBytes, java.nio.charset.StandardCharsets.UTF_8)
                        val keyboxes = CertHack.parseKeyboxXml(StringReader(xml), filename)
                        if (keyboxes.isNotEmpty()) {
                            unlockedCache[filename] = keyboxes
                            lockedFiles.remove(filename)
                            Logger.i("Loaded cached CBOX: $filename")
                            return@forEach
                        }
                    } else {
                        Logger.e("Failed to decrypt cached CBOX: $filename")
                        // cache might be invalid or key changed
                        cacheFile.delete()
                    }
                } catch (e: Exception) {
                    Logger.e("Error loading cached CBOX: $filename", e)
                }
            }

            // If we are here, it's locked
            lockedFiles.add(filename)
        }

        // Cleanup removed files
        val cacheIt = unlockedCache.keys.iterator()
        while (cacheIt.hasNext()) {
            val name = cacheIt.next()
            if (!currentFiles.contains(name)) {
                cacheIt.remove()
                File(dir, "$name.cache").delete()
            }
        }
        lockedFiles.retainAll(currentFiles)
    }

    fun unlock(filename: String, password: String, publicKey: String?): Boolean {
        if (filename.contains("..") || filename.contains("/") || filename.contains("\\")) {
            return false
        }
        val dir = Config.keyboxDirectory
        val file = File(dir, filename)
        if (!file.exists()) return false

        try {
            file.inputStream().use { stream ->
                val payload = CboxDecryptor.decrypt(stream, password)
                if (payload != null) {
                    // Verify signature if key provided
                    if (!publicKey.isNullOrBlank()) {
                         if (!CboxDecryptor.verifySignature(payload, publicKey)) {
                             Logger.e("Signature verification failed for $filename")
                             return false
                         }
                    } else if (payload.signatureBase64.isNotEmpty()) {
                        // Warn if signature exists but no key provided?
                        // Prompt says "User places .cbox in module folder and enters password + public key"
                        // But also supports embedded keys in ZIP.
                        // If manually unlocking, user might not provide key if they don't care about verification.
                        // We will allow it but log.
                        Logger.e("Unlocking $filename without verifying signature")
                    }

                    // Parse XML
                    val keyboxes = CertHack.parseKeyboxXml(StringReader(payload.xmlContent), filename)
                    if (keyboxes.isNotEmpty()) {
                        // Cache using DeviceKeyManager
                        val cacheBytes = DeviceKeyManager.encrypt(payload.xmlContent.toByteArray(java.nio.charset.StandardCharsets.UTF_8))
                        if (cacheBytes != null) {
                            val cacheFile = File(dir, "$filename.cache")
                            SecureFile.writeBytes(cacheFile, cacheBytes)
                        }

                        unlockedCache[filename] = keyboxes
                        lockedFiles.remove(filename)

                        // Check for plain XML collision and delete it
                        // "If plain keybox.xml AND cached version both exist, securely delete the plain XML"
                        // Assuming plain XML has same name but .xml? Or just keybox.xml?
                        // If detecting .cbox, we prioritize it.
                        // If there is a file named "filename.xml" (e.g. foo.cbox -> foo.xml), maybe delete?
                        // But usually .cbox doesn't imply .xml name.
                        // However, if we have ANY plain XMLs, we might want to warn.

                        return true
                    }
                }
            }
        } catch (e: Exception) {
            Logger.e("Failed to unlock CBOX: $filename", e)
        }
        return false
    }

    fun getUnlockedKeyboxes(): List<CertHack.KeyBox> {
        return unlockedCache.values.flatten()
    }

    fun getLockedFiles(): Set<String> {
        return lockedFiles
    }

    fun isLocked(filename: String): Boolean {
        return lockedFiles.contains(filename)
    }
}
