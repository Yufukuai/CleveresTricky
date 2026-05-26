package cleveres.tricky.cleverestech

import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.Tag
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.Authorization
import android.system.keystore2.IKeystoreSecurityLevel
import android.system.keystore2.KeyDescriptor
import android.system.keystore2.KeyEntryResponse
import android.system.keystore2.KeyMetadata
import cleveres.tricky.cleverestech.binder.BinderInterceptor
import cleveres.tricky.cleverestech.keystore.CertHack
import cleveres.tricky.cleverestech.keystore.CertHack.KeyGenParameters
import cleveres.tricky.cleverestech.keystore.Utils
import java.security.KeyPair
import java.security.cert.Certificate
import java.util.concurrent.ConcurrentHashMap
import java.util.LinkedList
import android.system.keystore2.CreateOperationResponse
import android.system.keystore2.IKeystoreOperation
import android.system.keystore2.OperationChallenge

import android.hardware.security.keymint.SecurityLevel
import android.os.SystemClock
class SecurityLevelInterceptor(
    private val original: IKeystoreSecurityLevel,
    private val level: Int
) : BinderInterceptor() {
    companion object {
        private val generateKeyTransaction =
            getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "generateKey")
        private val createOperationTransaction =
            getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "createOperation")

        val INTERCEPTED_CODES = intArrayOf(generateKeyTransaction, createOperationTransaction)
        private val keys = KeyCache<Key, Info>(1000)

        // Concurrent op tracking
        private val activeOps = ConcurrentHashMap<Int, LinkedList<Long>>()

        const val STRONGBOX_MAX_CONCURRENT_OPS = 4
        const val TEE_MAX_CONCURRENT_OPS = 15

        fun getKeyResponse(uid: Int, alias: String): KeyEntryResponse? =
            keys[Key(uid, alias)]?.response
    }

    data class Key(val uid: Int, val alias: String)
    data class Info(val keyPair: KeyPair, val response: KeyEntryResponse)

    private fun trackAndEnforceOpLimit(callingUid: Int): Boolean {
        val limit = if (level == SecurityLevel.STRONGBOX) STRONGBOX_MAX_CONCURRENT_OPS else TEE_MAX_CONCURRENT_OPS
        val now = SystemClock.uptimeMillis()

        var allowed = false
        activeOps.compute(callingUid) { _, existingOps ->
            val ops = existingOps ?: LinkedList()

            // Prune ops older than 10 seconds (arbitrary timeout to prevent leaks)
            while (ops.isNotEmpty() && now - (ops.firstOrNull() ?: 0L) > 10000) {
                ops.removeFirst()
            }

            if (ops.size >= limit) {
                // Evict oldest (LRU pruning) - simulate INVALID_OPERATION_HANDLE (-28) or TOO_MANY_OPERATIONS (-29)
                // In a real scenario we'd return a specific error code, but here we just reject the new one
                Logger.e("Concurrent operation limit exceeded for uid=$callingUid on level=$level (limit=$limit)")
                allowed = false
            } else {
                ops.addLast(now)
                allowed = true
            }
            ops
        }
        return allowed
    }

    override fun onPreTransact(
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel
    ): Result {
        if (code == createOperationTransaction && Config.needGenerate(callingUid)) {
            Logger.i("intercept createOperation uid=$callingUid pid=$callingPid")
            kotlin.runCatching {
                data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return@runCatching
                val operationParameters = data.createTypedArray(KeyParameter.CREATOR) ?: return@runCatching
                val forced = data.readBoolean()

                // Track and enforce op limit
                if (!trackAndEnforceOpLimit(callingUid)) {
                    // Return TOO_MANY_OPERATIONS (-29) equivalent in Parcel
                    val p = Parcel.obtain()
                    p.writeInt(-29) // TOO_MANY_OPERATIONS
                    return OverrideReply(-29, p)
                }

                // Domain handling: Allow Domain.APP (alias) or Domain.KEY_ID (nspace)
                val alias = if (keyDescriptor.domain == 0 /* Domain.APP */) keyDescriptor.alias
                           else keyDescriptor.nspace.toString()

                val keyInfo = keys[Key(callingUid, alias)]
                if (keyInfo != null) {
                    val kgp = KeyGenParameters(operationParameters)

                    // StrongBox param guard
                    if (level == SecurityLevel.STRONGBOX) {
                        if (keyInfo.keyPair.public.algorithm == "RSA" && kgp.keySize > 2048) {
                            Logger.e("StrongBox param guard: RSA > 2048 rejected")
                            return Skip // Forward to real HAL for proper rejection
                        }
                        if (kgp.ecCurveName != "secp256r1" && kgp.ecCurveName != null && kgp.ecCurveName.isNotEmpty()) {
                            Logger.e("StrongBox param guard: Non-P256 EC rejected")
                            return Skip // Forward to real HAL for proper rejection
                        }

                        // StrongBox timing simulation
                        // Note: Do NOT replace Thread.sleep with coroutines (e.g. runBlocking { delay() }).
                        // In Android Binder IPC interceptors (onPreTransact), execution is strictly synchronous.
                        // Non-blocking coroutines would break timing simulations by returning immediately,
                        // and runBlocking adds heavy overhead while still blocking the underlying thread.
                        val delay = if (kgp.purpose.contains(android.hardware.security.keymint.KeyPurpose.SIGN)) 80L else 250L
                        Thread.sleep(delay)
                    }

                    // For now, we don't fully emulate the crypto operation in software here,
                    // we just pass it down or mock a basic response if needed.
                    // To fully resolve TEE issues end-to-end, we might need to return a mocked CreateOperationResponse
                    // but usually just enforcing limits/timing/guards on the way down is enough if the HAL handles it
                    // OR if it's a software key, we'd need a local crypto proxy.
                    // For the scope of this update, we just let it Skip (fallthrough) AFTER tracking limits & timing,
                    // OR if it's a pure software mocked key, we might need to mock the response.
                    // Let's just track it and let the system handle it, or mock if we must.
                }
            }.onFailure {
                Logger.e("parse createOperation request", it)
            }
        }

        if (code == generateKeyTransaction && Config.needGenerate(callingUid)) {
            Logger.i("intercept key gen uid=$callingUid pid=$callingPid")
            kotlin.runCatching {
                data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                val keyDescriptor =
                    data.readTypedObject(KeyDescriptor.CREATOR) ?: return@runCatching
                val attestationKeyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
                val params = data.createTypedArray(KeyParameter.CREATOR)!!
                // val aFlags = data.readInt()
                // val entropy = data.createByteArray()
                val kgp = KeyGenParameters(params)
                if (kgp.attestationChallenge != null) {
                    var issuerKeyPair: KeyPair? = null
                    var issuerChain: List<Certificate>? = null

                    if (attestationKeyDescriptor != null) {
                        Logger.i("intercept attestation key request alias=${attestationKeyDescriptor.alias}")
                        val keyInfo = keys[Key(callingUid, attestationKeyDescriptor.alias)]
                        if (keyInfo != null) {
                            issuerKeyPair = keyInfo.keyPair
                            issuerChain = Utils.getCertificateChain(keyInfo.response)?.toList()
                            Logger.i("found cached attest key: ${attestationKeyDescriptor.alias}")
                        } else {
                            Logger.e("attest key not found in cache: ${attestationKeyDescriptor.alias}, falling back to root")
                        }
                    }
                    val startNanos = System.nanoTime()
                    val pair = CertHack.generateKeyPair(callingUid, keyDescriptor, kgp, issuerKeyPair, issuerChain)
                        ?: return@runCatching
                    cleveres.tricky.cleverestech.util.TeeLatencySimulator.simulateGenerateKeyDelay(kgp.algorithm, System.nanoTime() - startNanos)
                    val response = buildResponse(pair.second, kgp, keyDescriptor, callingUid)
                    keys[Key(callingUid, keyDescriptor.alias)] = Info(pair.first, response)
                    val p = Parcel.obtain()
                    p.writeNoException()
                    p.writeTypedObject(response.metadata, 0)
                    return OverrideReply(0, p)
                }
            }.onFailure {
                Logger.e("parse key gen request", it)
            }
        }
        return Skip
    }

    private fun buildResponse(
        chain: List<Certificate>,
        params: KeyGenParameters,
        descriptor: KeyDescriptor,
        callingUid: Int
    ): KeyEntryResponse {
        val response = KeyEntryResponse()
        val metadata = KeyMetadata()
        metadata.keySecurityLevel = level
        Utils.putCertificateChain(metadata, chain.toTypedArray<Certificate>())
        val d = KeyDescriptor()
        d.domain = descriptor.domain
        d.nspace = descriptor.nspace
        metadata.key = d
        val authorizations = ArrayList<Authorization>(params.purpose.size + params.digest.size + 6)

        fun addAuth(tag: Int, value: KeyParameterValue) {
            val a = Authorization()
            a.keyParameter = KeyParameter()
            a.keyParameter.tag = tag
            a.keyParameter.value = value
            a.securityLevel = level
            authorizations.add(a)
        }

        val purposeSize = params.purpose.size
        for (idx in 0 until purposeSize) {
            val i = params.purpose[idx]
            addAuth(Tag.PURPOSE, KeyParameterValue.keyPurpose(i))
        }
        val digestSize = params.digest.size
        for (idx in 0 until digestSize) {
            val i = params.digest[idx]
            addAuth(Tag.DIGEST, KeyParameterValue.digest(i))
        }
        val blockModeSize = params.blockMode.size
        for (idx in 0 until blockModeSize) {
            val i = params.blockMode[idx]
            addAuth(Tag.BLOCK_MODE, KeyParameterValue.blockMode(i))
        }
        val paddingSize = params.padding.size
        for (idx in 0 until paddingSize) {
            val i = params.padding[idx]
            addAuth(Tag.PADDING, KeyParameterValue.paddingMode(i))
        }
        val mgfDigestSize = params.mgfDigest.size
        for (idx in 0 until mgfDigestSize) {
            val i = params.mgfDigest[idx]
            addAuth(Tag.RSA_OAEP_MGF_DIGEST, KeyParameterValue.digest(i))
        }
        addAuth(Tag.ALGORITHM, KeyParameterValue.algorithm(params.algorithm))
        addAuth(Tag.KEY_SIZE, KeyParameterValue.integer(params.keySize))
        addAuth(Tag.EC_CURVE, KeyParameterValue.ecCurve(params.ecCurve))
        if (params.isNoAuthRequired) {
            addAuth(Tag.NO_AUTH_REQUIRED, KeyParameterValue.boolValue(true))
        }
        addAuth(Tag.ORIGIN, KeyParameterValue.origin(0 /* KeyOrigin.GENERATED */))
        addAuth(Tag.OS_VERSION, KeyParameterValue.integer(osVersion))
        addAuth(Tag.OS_PATCHLEVEL, KeyParameterValue.integer(patchLevel))
        addAuth(Tag.VENDOR_PATCHLEVEL, KeyParameterValue.integer(patchLevelLong))
        addAuth(Tag.BOOT_PATCHLEVEL, KeyParameterValue.integer(patchLevelLong))
        addAuth(Tag.CREATION_DATETIME, KeyParameterValue.dateTime(System.currentTimeMillis()))
        addAuth(Tag.USER_ID, KeyParameterValue.integer(callingUid / 100000))

        metadata.authorizations = authorizations.toTypedArray<Authorization>()
        response.metadata = metadata
        response.iSecurityLevel = original
        return response
    }
}
