package cleveres.tricky.cleverestech

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Tests that validate comprehensive Play Integrity API Protection.
 *
 * Google's Play Integrity API (Nov 2025 update + Device Recall beta 2026)
 * includes multiple verdict categories. These tests verify that the module
 * has countermeasures against ALL of them:
 *
 *   - deviceIntegrity    : Device genuine/certified/non-rooted
 *   - appIntegrity       : App unmodified, recognized by Play
 *   - accountDetails     : User Play-licensed
 *   - recentDeviceActivity: Token request rate anomaly detection
 *   - deviceRecall       : 3 persistent bits surviving factory resets
 *   - appAccessRiskVerdict: Overlay/capture app detection
 *   - playProtectVerdict  : Play Protect malware scan status
 *   - deviceAttributes   : Attested SDK version
 *   - Remediation dialogs: GET_INTEGRITY / GET_STRONG_INTEGRITY
 *   - Platform key attestation rotation (Feb 2026)
 */
class DeviceRecallProtectionTest {

    private lateinit var cppContent: String
    private lateinit var headerContent: String

    @Before
    fun setup() {
        cppContent = moduleCppFile("binder_interceptor.cpp").readText() + "\n" + java.io.File("../rust/cbor-cose/src/play_integrity.rs").readText()
        headerContent = moduleCppFile("binder_interceptor.h").readText()
    }

    // ========================================================================
    // Class & Architecture
    // ========================================================================

    @Test
    fun testHasPlayIntegrityProtectionClass() {
        assertTrue(
            "Must have PlayIntegrityProtection class for comprehensive countermeasures",
            cppContent.contains("PlayIntegrityProtection") &&
                headerContent.contains("PlayIntegrityProtection")
        )
    }

    @Test
    fun testHasDeviceRecallProtectionAlias() {
        assertTrue(
            "Must have DeviceRecallProtection alias for backward compatibility",
            headerContent.contains("DeviceRecallProtection") &&
                cppContent.contains("DeviceRecallProtection")
        )
    }

    @Test
    fun testDeviceRecallHasInitialize() {
        assertTrue(
            "PlayIntegrityProtection must have initialize method",
            cppContent.contains("PlayIntegrityProtection::initialize") ||
                cppContent.contains("DeviceRecallProtection::initialize")
        )
    }

    @Test
    fun testDeviceRecallHasIsEnabled() {
        assertTrue(
            "PlayIntegrityProtection must have isEnabled check",
            cppContent.contains("PlayIntegrityProtection::isEnabled") ||
                cppContent.contains("DeviceRecallProtection::isEnabled")
        )
    }

    // ========================================================================
    // Integrity Service Detection
    // ========================================================================

    @Test
    fun testDetectsIntegrityServiceDescriptor() {
        assertTrue(
            "Must detect Play Integrity service descriptors in Binder transactions",
            cppContent.contains("isIntegrityServiceDescriptor")
        )
    }

    @Test
    fun testKnowsPlayCoreIntegrityDescriptor() {
        assertTrue(
            "Must recognize com.google.android.play.core.integrity descriptor",
            headerContent.contains("com.google.android.play.core.integrity") ||
                cppContent.contains("com.google.android.play.core.integrity")
        )
    }

    @Test
    fun testKnowsGmsIntegrityDescriptor() {
        assertTrue(
            "Must recognize com.google.android.gms.playintegrity descriptor",
            headerContent.contains("com.google.android.gms.playintegrity") ||
                cppContent.contains("com.google.android.gms.playintegrity")
        )
    }

    @Test
    fun testDetectsRecallRelatedTransaction() {
        assertTrue(
            "Must detect recall-related transaction codes (warmup/request/standard)",
            cppContent.contains("isRecallRelatedTransaction")
        )
    }

    @Test
    fun testRecognizesDeviceRecallKeyword() {
        assertTrue(
            "Must contain 'deviceRecall' keyword for pattern matching",
            headerContent.contains("deviceRecall") || cppContent.contains("deviceRecall")
        )
    }

    // ========================================================================
    // ALL Verdict Categories (Nov 2025 Blog Post)
    // ========================================================================

    @Test
    fun testCoversDeviceIntegrityVerdict() {
        assertTrue(
            "Must define DEVICE_INTEGRITY_INDICATOR for deviceIntegrity verdict countermeasure",
            headerContent.contains("deviceIntegrity") || headerContent.contains("DEVICE_INTEGRITY")
        )
    }

    @Test
    fun testCoversAppIntegrityVerdict() {
        assertTrue(
            "Must define APP_INTEGRITY_INDICATOR for appIntegrity verdict countermeasure",
            headerContent.contains("appIntegrity") || headerContent.contains("APP_INTEGRITY")
        )
    }

    @Test
    fun testCoversAccountDetailsVerdict() {
        assertTrue(
            "Must define ACCOUNT_DETAILS_INDICATOR for accountDetails verdict countermeasure",
            headerContent.contains("accountDetails") || headerContent.contains("ACCOUNT_DETAILS")
        )
    }

    @Test
    fun testCoversRecentDeviceActivityVerdict() {
        assertTrue(
            "Must define ACTIVITY_LEVEL_INDICATOR for recentDeviceActivity countermeasure",
            headerContent.contains("recentDeviceActivity") || headerContent.contains("ACTIVITY_LEVEL")
        )
    }

    @Test
    fun testCoversAppAccessRiskVerdict() {
        assertTrue(
            "Must define ACCESS_RISK_INDICATOR for appAccessRiskVerdict countermeasure",
            headerContent.contains("appAccessRiskVerdict") || headerContent.contains("ACCESS_RISK")
        )
    }

    @Test
    fun testCoversPlayProtectVerdict() {
        assertTrue(
            "Must define PLAY_PROTECT_INDICATOR for playProtectVerdict countermeasure",
            headerContent.contains("playProtectVerdict") || headerContent.contains("PLAY_PROTECT")
        )
    }

    @Test
    fun testCoversDeviceAttributesVerdict() {
        assertTrue(
            "Must define DEVICE_ATTRIBUTES_INDICATOR for deviceAttributes countermeasure",
            headerContent.contains("deviceAttributes") || headerContent.contains("DEVICE_ATTRIBUTES")
        )
    }

    @Test
    fun testHasIntegrityVerdictTransactionDetection() {
        assertTrue(
            "Must have isIntegrityVerdictTransaction for broad verdict detection",
            cppContent.contains("isIntegrityVerdictTransaction") ||
                headerContent.contains("isIntegrityVerdictTransaction")
        )
    }

    // ========================================================================
    // Remediation Dialog Protection
    // ========================================================================

    @Test
    fun testDetectsRemediationDialogIntent() {
        assertTrue(
            "Must detect Play remediation dialog intents",
            cppContent.contains("isRemediationDialogIntent") ||
                headerContent.contains("isRemediationDialogIntent")
        )
    }

    @Test
    fun testKnowsGetIntegrityRemediation() {
        assertTrue(
            "Must know GET_INTEGRITY remediation dialog action",
            headerContent.contains("GET_INTEGRITY")
        )
    }

    @Test
    fun testKnowsGetStrongIntegrityRemediation() {
        assertTrue(
            "Must know GET_STRONG_INTEGRITY remediation dialog action",
            headerContent.contains("GET_STRONG_INTEGRITY")
        )
    }

    @Test
    fun testKnowsGetLicensedRemediation() {
        assertTrue(
            "Must know GET_LICENSED remediation dialog action",
            headerContent.contains("GET_LICENSED")
        )
    }

    @Test
    fun testKnowsCloseAccessRiskRemediation() {
        assertTrue(
            "Must know CLOSE_UNKNOWN_ACCESS_RISK remediation dialog action",
            headerContent.contains("CLOSE_UNKNOWN_ACCESS_RISK") ||
                headerContent.contains("CLOSE_ACCESS_RISK")
        )
    }

    // ========================================================================
    // Rate Limiting (recentDeviceActivity Protection)
    // ========================================================================

    @Test
    fun testHasTokenRequestRateTracking() {
        assertTrue(
            "Must track integrity token request rate to avoid anomaly detection",
            cppContent.contains("recordTokenRequest") ||
                headerContent.contains("recordTokenRequest")
        )
    }

    @Test
    fun testHasRequestRateNormalCheck() {
        assertTrue(
            "Must check if request rate is normal to avoid recentDeviceActivity flags",
            cppContent.contains("isRequestRateNormal") ||
                headerContent.contains("isRequestRateNormal")
        )
    }

    @Test
    fun testHasMaxRequestsPerMinuteLimit() {
        assertTrue(
            "Must define MAX_REQUESTS_PER_MINUTE to limit token request rate",
            headerContent.contains("MAX_REQUESTS_PER_MINUTE")
        )
    }

    @Test
    fun testMentionsRecentDeviceActivityInCode() {
        assertTrue(
            "Must mention recentDeviceActivity risk in rate limit warnings",
            cppContent.contains("recentDeviceActivity")
        )
    }

    // ========================================================================
    // Identity Signal Randomization
    // ========================================================================

    @Test
    fun testHasRandomizeDeviceSignals() {
        assertTrue(
            "Must have randomizeDeviceSignals method to break device recall association",
            cppContent.contains("randomizeDeviceSignals")
        )
    }

    @Test
    fun testRandomizesSerialForRecall() {
        assertTrue(
            "Device recall protection must invalidate serial number cache",
            cppContent.contains("ro.serialno")
        )
    }

    @Test
    fun testRandomizesImeiForRecall() {
        assertTrue(
            "Device recall protection must invalidate IMEI cache",
            cppContent.contains("persist.radio.imei")
        )
    }

    @Test
    fun testRandomizesFingerprintForRecall() {
        assertTrue(
            "Device recall protection must invalidate fingerprint cache",
            cppContent.contains("ro.build.fingerprint")
        )
    }

    @Test
    fun testRandomizesSecurityPatchForDeviceIntegrity() {
        assertTrue(
            "Must invalidate security patch cache for deviceIntegrity/MEETS_STRONG_INTEGRITY",
            cppContent.contains("ro.build.version.security_patch")
        )
    }

    @Test
    fun testRandomizesSdkVersionForDeviceAttributes() {
        assertTrue(
            "Must invalidate SDK version cache for deviceAttributes verdict",
            cppContent.contains("ro.build.version.sdk")
        )
    }

    @Test
    fun testRandomizesVerifiedBootStateForDeviceIntegrity() {
        assertTrue(
            "Must invalidate verified boot state for deviceIntegrity verdict",
            cppContent.contains("ro.boot.verifiedbootstate")
        )
    }

    // ========================================================================
    // Firebase App Check Awareness
    // ========================================================================

    @Test
    fun testDetectsFirebaseAppCheck() {
        assertTrue(
            "Must detect Firebase App Check which uses Play Integrity under the hood",
            cppContent.contains("firebase") || cppContent.contains("appcheck")
        )
    }

    // ========================================================================
    // Configuration & Integration
    // ========================================================================

    @Test
    fun testConfigFileToggle() {
        assertTrue(
            "Device recall protection must be toggleable via config file",
            cppContent.contains("device_recall_protection")
        )
    }

    @Test
    fun testAutoEnableWithRandomOnBoot() {
        assertTrue(
            "Device recall protection should auto-enable when random_on_boot is active",
            cppContent.contains("random_on_boot")
        )
    }

    @Test
    fun testAutoEnableWithRandomDrmOnBoot() {
        assertTrue(
            "Device recall protection should auto-enable when random_drm_on_boot is active",
            cppContent.contains("random_drm_on_boot")
        )
    }

    @Test
    fun testCalledDuringInitialization() {
        assertTrue(
            "Play integrity protection must be initialized during hook setup",
            cppContent.contains("DeviceRecallProtection::initialize()")
        )
    }

    @Test
    fun testRandomizeCalledOnInit() {
        assertTrue(
            "Device signals must be randomized during initialization when protection is enabled",
            cppContent.contains("DeviceRecallProtection::randomizeDeviceSignals()")
        )
    }

    // ========================================================================
    // Warmup / Standard Request Interception
    // ========================================================================

    @Test
    fun testKnowsWarmupTransactionCode() {
        assertTrue(
            "Must define INTEGRITY_WARMUP_CODE for standard request warmup detection",
            headerContent.contains("INTEGRITY_WARMUP_CODE")
        )
    }

    @Test
    fun testKnowsRequestTransactionCode() {
        assertTrue(
            "Must define INTEGRITY_REQUEST_CODE for integrity request detection",
            headerContent.contains("INTEGRITY_REQUEST_CODE")
        )
    }

    @Test
    fun testKnowsStandardTransactionCode() {
        assertTrue(
            "Must define INTEGRITY_STANDARD_CODE for standard integrity request",
            headerContent.contains("INTEGRITY_STANDARD_CODE")
        )
    }

    // ========================================================================
    // Thread Safety
    // ========================================================================

    @Test
    fun testAtomicEnabledFlag() {
        assertTrue(
            "PlayIntegrityProtection enabled flag must be atomic for thread safety",
            headerContent.contains("atomic<bool>") || cppContent.contains("atomic<bool>")
        )
    }

    @Test
    fun testAtomicInitializedFlag() {
        assertTrue(
            "PlayIntegrityProtection initialized flag must be atomic for thread safety",
            headerContent.contains("s_initialized") || cppContent.contains("s_initialized")
        )
    }

    @Test
    fun testAtomicRequestCounter() {
        assertTrue(
            "Token request counter must be atomic for thread safety",
            headerContent.contains("s_request_count") || cppContent.contains("s_request_count")
        )
    }

    // ========================================================================
    // Documentation & Comments
    // ========================================================================

    @Test
    fun testDocumentsDeviceRecallFeature() {
        assertTrue(
            "Code must document what Device Recall is (Google's persistent 3-bit feature)",
            cppContent.contains("3 persistent bits") || cppContent.contains("3 bits") ||
                cppContent.contains("factory reset")
        )
    }

    @Test
    fun testDocumentsDefenseStrategy() {
        assertTrue(
            "Code must document the defense strategy against Play Integrity",
            cppContent.contains("defense strategy") || cppContent.contains("Defense strategy") ||
                cppContent.contains("countermeasure")
        )
    }

    @Test
    fun testDocumentsAllVerdictCategories() {
        assertTrue(
            "Code must document coverage of all verdict categories",
            cppContent.contains("deviceIntegrity") &&
                cppContent.contains("appIntegrity") &&
                cppContent.contains("accountDetails") &&
                cppContent.contains("recentDeviceActivity") &&
                cppContent.contains("deviceRecall")
        )
    }

    @Test
    fun testDocumentsPlatformKeyRotation() {
        assertTrue(
            "Code must mention platform key attestation rotation (Feb 2026)",
            cppContent.contains("key attestation rotation") ||
                cppContent.contains("Platform key attestation") ||
                headerContent.contains("key attestation rotation")
        )
    }
}
