package cleveres.tricky.cleverestech.util

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import cleveres.tricky.cleverestech.Logger

object DeviceKeyManager {
    private const val KEY_ALIAS = "cleveres_device_cache_key"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val AES_MODE = "AES/GCM/NoPadding"
    private const val TAG = "DeviceKeyManager"

    // Fallback if AndroidKeyStore is unavailable (e.g. some root environments)
    @Volatile
    private var fallbackKey: SecretKey? = null
    @Volatile
    private var useFallback = false

    @Volatile
    private var cachedKey: SecretKey? = null

    fun initialize(rootDir: File) {
        try {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE)
            ks.load(null)
            if (!ks.containsAlias(KEY_ALIAS)) {
                val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
                keyGenerator.init(
                    KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setKeySize(256)
                        .build()
                )
                keyGenerator.generateKey()
            }
            // Test access
            ks.getEntry(KEY_ALIAS, null)
        } catch (e: Throwable) {
            Logger.e("$TAG: AndroidKeyStore failed, using fallback file key: ${e.message}")
            useFallback = true
            loadFallbackKey(rootDir)
        }
    }

    private fun loadFallbackKey(rootDir: File) {
        val keyFile = File(rootDir, "device_secret.key")
        if (keyFile.exists()) {
            val bytes = keyFile.readBytes()
            if (bytes.size == 32) {
                fallbackKey = SecretKeySpec(bytes, "AES")
                return
            }
        }
        // Generate new
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        fallbackKey = SecretKeySpec(bytes, "AES")
        SecureFile.writeBytes(keyFile, bytes)
        // chmod 600
        try {
            android.system.Os.chmod(keyFile.absolutePath, 384)
        } catch (e: Exception) {
            Logger.e("$TAG: Failed to chmod fallback key", e)
        }
    }

    private fun getKey(): SecretKey? {
        if (useFallback) return fallbackKey
        cachedKey?.let { return it }

        synchronized(this) {
            cachedKey?.let { return it }
            return try {
                val ks = KeyStore.getInstance(ANDROID_KEYSTORE)
                ks.load(null)
                val entry = ks.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry
                cachedKey = entry?.secretKey
                cachedKey
            } catch (e: Exception) {
                null
            }
        }
    }

    fun encrypt(data: ByteArray): ByteArray? {
        try {
            val key = getKey() ?: return null
            val cipher = Cipher.getInstance(AES_MODE)
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val iv = cipher.iv
            val ciphertext = cipher.doFinal(data)

            // Format: [1 byte IV len] [IV] [ciphertext]
            // Standard GCM IV is 12 bytes
            val result = ByteArray(1 + iv.size + ciphertext.size)
            result[0] = iv.size.toByte()
            System.arraycopy(iv, 0, result, 1, iv.size)
            System.arraycopy(ciphertext, 0, result, 1 + iv.size, ciphertext.size)
            return result
        } catch (e: Exception) {
            Logger.e("$TAG: Encrypt failed", e)
            return null
        }
    }

    fun decrypt(data: ByteArray): ByteArray? {
        try {
            val key = getKey() ?: return null
            if (data.isEmpty()) return null

            val ivLen = data[0].toInt() and 0xFF
            if (ivLen > data.size - 1) return null

            val iv = ByteArray(ivLen)
            System.arraycopy(data, 1, iv, 0, ivLen)

            val ciphertextLen = data.size - 1 - ivLen
            val ciphertext = ByteArray(ciphertextLen)
            System.arraycopy(data, 1 + ivLen, ciphertext, 0, ciphertextLen)

            val cipher = Cipher.getInstance(AES_MODE)
            val spec = GCMParameterSpec(128, iv)
            cipher.init(Cipher.DECRYPT_MODE, key, spec)
            return cipher.doFinal(ciphertext)
        } catch (e: Exception) {
            Logger.e("$TAG: Decrypt failed", e)
            return null
        }
    }
}
