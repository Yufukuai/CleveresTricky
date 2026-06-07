package cleveres.tricky.cleverestech

import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder

object VbMetaParser {
    // AVB0 Magic (4 bytes)
    private val AVB_MAGIC = "AVB0".toByteArray()
    private const val HEADER_SIZE = 256
    private const val AUTH_DATA_BLOCK_SIZE_LOC = 12
    private const val PUBLIC_KEY_OFFSET_LOC = 64
    private const val PUBLIC_KEY_SIZE_LOC = 72

    /**
     * Extracts the public key from the vbmeta image at the given path.
     * Returns null if the file cannot be read or parsing fails.
     */
    fun extractPublicKey(path: String): ByteArray? {
        return try {
            RandomAccessFile(path, "r").use { file ->
                // Read header
                val header = ByteArray(HEADER_SIZE)
                if (file.read(header) != HEADER_SIZE) {
                    Logger.e("VbMetaParser: Failed to read header from $path")
                    return null
                }

                // Verify Magic
                for (i in AVB_MAGIC.indices) {
                    if (header[i] != AVB_MAGIC[i]) {
                        Logger.e("VbMetaParser: Invalid magic in $path")
                        return null
                    }
                }

                val buffer = ByteBuffer.wrap(header).order(ByteOrder.BIG_ENDIAN)
                val authDataBlockSize = buffer.getLong(AUTH_DATA_BLOCK_SIZE_LOC)
                val publicKeyOffset = buffer.getLong(PUBLIC_KEY_OFFSET_LOC)
                val publicKeySize = buffer.getLong(PUBLIC_KEY_SIZE_LOC)

                if (publicKeyOffset < 0 || publicKeySize <= 0 || authDataBlockSize < 0) {
                    Logger.e("VbMetaParser: Invalid offset ($publicKeyOffset), size ($publicKeySize), or auth data size ($authDataBlockSize)")
                    return null
                }

                // Seek to public key location
                // The public key is in the Auxiliary Data block, which follows the Authentication Data block.
                // The Authentication Data block starts at HEADER_SIZE (256).
                // So the Auxiliary Data block starts at HEADER_SIZE + authDataBlockSize.
                // publicKeyOffset is relative to the start of the Auxiliary Data block.

                val absoluteOffset = HEADER_SIZE + authDataBlockSize + publicKeyOffset
                file.seek(absoluteOffset)

                // Sanity check: cap at 16MB to prevent OOM from malformed vbmeta
                if (publicKeySize > 16 * 1024 * 1024) {
                    Logger.e("VbMetaParser: Unreasonable public key size: $publicKeySize")
                    return null
                }

                val keyBytes = ByteArray(publicKeySize.toInt())
                if (file.read(keyBytes) != keyBytes.size) {
                    Logger.e("VbMetaParser: Failed to read public key bytes")
                    return null
                }

                Logger.d("VbMetaParser: Successfully extracted public key from $path")
                keyBytes
            }
        } catch (e: Exception) {
            Logger.e("VbMetaParser: Error reading $path", e)
            null
        }
    }
}
