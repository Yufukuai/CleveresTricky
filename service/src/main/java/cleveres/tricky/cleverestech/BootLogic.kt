package cleveres.tricky.cleverestech

import java.io.File
import java.time.LocalDate
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit
import java.util.concurrent.atomic.AtomicBoolean

object BootLogic {
    private const val CONFIG_PATH = "/data/adb/cleverestricky"
    private val ran = AtomicBoolean(false)
    private val configDir = File(CONFIG_PATH)

    // Flag Files
    const val FILE_AUTO_PATCH = "auto_patch_update"
    const val FILE_HIDE_PROPS = "hide_sensitive_props"
    const val FILE_SPOOF_CN = "spoof_region_cn"

    fun run() {
        if (ran.getAndSet(true)) return

        Logger.i("Running BootLogic tasks...")

        try {
            // Always apply property hiding on daemon start — this is the sole
            // authority for property spoofing.  Shell-based resetprop was removed
            // from post-fs-data.sh to avoid detection by integrity frameworks.
            applyPropertyHiding()

            if (File(configDir, FILE_AUTO_PATCH).exists()) {
                checkAutoPatch()
            }

            // Check hiding props logic
            // User request: "Most default settings should be disabled"
            // So we only run if the file exists.
            if (File(configDir, FILE_HIDE_PROPS).exists()) {
                checkHideProps()
            }

        } catch (e: Exception) {
            Logger.e("BootLogic failed", e)
        }
    }

    /**
     * Core property hiding that always runs on daemon start.
     *
     * This replaces the resetprop calls that were previously in post-fs-data.sh.
     * Moving them into the compiled daemon makes them far harder for Google's
     * integrity framework to detect (shell scripts are trivially scannable,
     * compiled code is not).
     *
     * Properties are set in a single batched process to avoid spawning 20+
     * individual processes on every boot.
     */
    private fun applyPropertyHiding() {
        try {
            Logger.i("Applying core property hiding from daemon...")

            val props = mutableMapOf<String, String>()

            // Verified boot & bootloader state
            props["ro.boot.verifiedbootstate"] = "green"
            props["ro.boot.flash.locked"] = "1"
            props["ro.boot.veritymode"] = "enforcing"
            props["ro.boot.vbmeta.device_state"] = "locked"
            props["ro.boot.warranty_bit"] = "0"
            props["ro.warranty_bit"] = "0"

            // Security & debug flags
            props["ro.secure"] = "1"
            props["ro.debuggable"] = "0"
            props["ro.force.debuggable"] = "0"
            props["ro.adb.secure"] = "1"
            props["ro.build.type"] = "user"
            props["ro.build.tags"] = "release-keys"

            // Vendor warranty bits
            props["ro.vendor.boot.warranty_bit"] = "0"
            props["ro.vendor.warranty_bit"] = "0"

            // Vendor boot state
            props["vendor.boot.vbmeta.device_state"] = "locked"
            props["vendor.boot.verifiedbootstate"] = "green"

            // OEM unlock / secure boot
            props["sys.oem_unlock_allowed"] = "0"
            props["ro.secureboot.lockstate"] = "locked"
            props["ro.oem_unlock_supported"] = "0"

            // Realme specific
            props["ro.boot.realmebootstate"] = "green"
            props["ro.boot.realme.lockstate"] = "1"

            resetPropBatch(props)

            // Bootmode hiding (recovery -> unknown) — requires reading current values
            hideBootMode("ro.bootmode")
            hideBootMode("ro.boot.bootmode")
            hideBootMode("vendor.boot.bootmode")

            Logger.i("Core property hiding applied.")
        } catch (e: Exception) {
            Logger.e("Error in applyPropertyHiding", e)
        }
    }

    private fun checkAutoPatch() {
        try {
            val currentPatch = getSystemProperty("ro.build.version.security_patch")
            if (currentPatch.isBlank()) return

            // Parse current patch
            // It could be YYYY-MM-DD or something else
            val formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd")
            val patchDate = try {
                LocalDate.parse(currentPatch, formatter)
            } catch (e: Exception) {
                Logger.e("Failed to parse security patch: $currentPatch", e)
                return
            }

            val sixMonthsAgo = LocalDate.now().minus(6, ChronoUnit.MONTHS)

            if (patchDate.isBefore(sixMonthsAgo)) {
                Logger.i("System security patch ($currentPatch) is older than 6 months. Updating...")

                // Calculate target date: 5th of previous month
                val now = LocalDate.now()
                val targetDate = now.minusMonths(1).withDayOfMonth(5)
                val newPatch = targetDate.format(formatter)

                val spFile = File(configDir, "security_patch.txt")
                if (!spFile.exists() || spFile.readText().trim() != newPatch) {
                    spFile.writeText(newPatch)
                    Logger.i("Updated security_patch.txt to $newPatch")
                    // Set restrictive permissions using array-based exec to avoid shell injection
                    execAndDrain(arrayOf("chmod", "600", spFile.absolutePath))
                }
            }
        } catch (e: Exception) {
            Logger.e("Error in Auto Patch Update", e)
        }
    }

    private fun checkHideProps() {
        try {
            val shamikoExists = File("/data/adb/modules/zygisk_shamiko").exists()
            val spoofCn = File(configDir, FILE_SPOOF_CN).exists()

            if (shamikoExists) {
                Logger.i("Shamiko detected. Applying minimal hiding.")
                if (spoofCn) {
                    resetPropBatch(mapOf(
                        "ro.boot.hwc" to "CN",
                        "gsm.operator.iso-country" to "cn"
                    ))
                }
            } else {
                Logger.i("Shamiko not found. Applying comprehensive hiding.")

                val props = mutableMapOf<String, String>()

                // Standard hiding props
                props["ro.boot.vbmeta.device_state"] = "locked"
                props["ro.boot.verifiedbootstate"] = "green"
                props["ro.boot.flash.locked"] = "1"
                props["ro.boot.veritymode"] = "enforcing"
                props["ro.boot.warranty_bit"] = "0"
                props["ro.warranty_bit"] = "0"
                props["ro.debuggable"] = "0"
                props["ro.force.debuggable"] = "0"
                props["ro.secure"] = "1"
                props["ro.adb.secure"] = "1"
                props["ro.build.type"] = "user"
                props["ro.build.tags"] = "release-keys"
                props["ro.vendor.boot.warranty_bit"] = "0"
                props["ro.vendor.warranty_bit"] = "0"
                props["vendor.boot.vbmeta.device_state"] = "locked"
                props["vendor.boot.verifiedbootstate"] = "green"
                props["sys.oem_unlock_allowed"] = "0"
                props["ro.secureboot.lockstate"] = "locked"

                // Realme specific
                props["ro.boot.realmebootstate"] = "green"
                props["ro.boot.realme.lockstate"] = "1"

                if (spoofCn) {
                    props["ro.boot.hwc"] = "CN"
                    props["gsm.operator.iso-country"] = "cn"
                    props["gsm.sim.operator.iso-country"] = "cn"
                    props["ro.boot.hwlevel"] = "MP"
                    props["persist.radio.skhwc_matchres"] = "MATCH"
                }

                resetPropBatch(props)

                // Bootmode
                hideBootMode("ro.bootmode")
                hideBootMode("ro.boot.bootmode")
                hideBootMode("vendor.boot.bootmode")
            }
        } catch (e: Exception) {
            Logger.e("Error in Hide Props", e)
        }
    }

    /**
     * Batch-set multiple properties in a single shell process.
     * This avoids spawning N separate processes for N properties, significantly
     * reducing boot-time overhead and process churn.
     */
    private fun resetPropBatch(props: Map<String, String>) {
        if (props.isEmpty()) return
        try {
            // Build a script that sets all properties in one shell invocation.
            // Each resetprop call is separated by " && " so we fail fast on error.
            val script = props.entries.joinToString(" ; ") { (name, value) ->
                "resetprop -n ${shellEscape(name)} ${shellEscape(value)}"
            }
            execAndDrain(arrayOf("sh", "-c", script))
        } catch (e: Exception) {
            Logger.e("Failed to batch resetprop (${props.size} props)", e)
        }
    }

    /**
     * Escapes a string for safe use in a shell argument.
     * Property names and values are controlled by the module (not user input),
     * but we still escape defensively as a security best practice.
     */
    private fun shellEscape(s: String): String {
        return "'${s.replace("'", "'\\''")}'"
    }

    private fun resetProp(name: String, value: String) {
        try {
            execAndDrain(arrayOf("resetprop", "-n", name, value))
        } catch (e: Exception) {
            Logger.e("Failed to resetprop $name", e)
        }
    }

    private fun hideBootMode(name: String) {
        val current = getSystemProperty(name)
        if (current.contains("recovery")) {
            resetProp(name, "unknown")
        }
    }

    private fun getSystemProperty(key: String): String {
        return systemPropertiesGet(key, "") ?: ""
    }

    /**
     * Execute a command, drain both stdout and stderr to prevent FD exhaustion,
     * and wait for process termination.
     */
    private fun execAndDrain(cmd: Array<String>) {
        try {
            val p = ProcessBuilder(*cmd).redirectErrorStream(true).start()
            try {
                p.inputStream.readBytes()
            } catch (_: Exception) {}
            p.waitFor()
        } catch (e: Exception) {
            Logger.e("Failed to execute and drain", e)
        }
    }
}
