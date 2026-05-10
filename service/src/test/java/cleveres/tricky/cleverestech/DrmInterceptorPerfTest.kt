package cleveres.tricky.cleverestech

import org.junit.Test
import kotlin.system.measureNanoTime

class DrmInterceptorPerfTest {

    private val DRM_PROCESS_NAMES_LIST = listOf(
        "android.hardware.drm-service.widevine",
        "android.hardware.drm-service.clearkey",
        "android.hardware.drm@1.4-service.widevine",
        "android.hardware.drm@1.3-service.widevine",
        "android.hardware.drm@1.2-service.widevine",
        "mediadrmserver",
        "vendor.samsung.hardware.drm-service.widevine"
    )

    private val DRM_PROCESS_NAMES_SET = DRM_PROCESS_NAMES_LIST.toSet()

    private val TEST_INPUTS = listOf(
        "android.hardware.drm-service.widevine",
        "/vendor/bin/hw/android.hardware.drm-service.widevine",
        "mediadrmserver",
        "/system/bin/mediadrmserver",
        "some.other.process",
        "/system/bin/init",
        "vendor.samsung.hardware.drm-service.widevine",
        "/vendor/bin/hw/vendor.samsung.hardware.drm-service.widevine"
    )

    @Test
    fun benchmarkLookup() {
        val iterations = 100_000

        // Warmup
        repeat(10_000) {
            for (input in TEST_INPUTS) {
                // Old logic
                for (target in DRM_PROCESS_NAMES_LIST) {
                    if (input == target || input.endsWith("/$target")) {
                        break
                    }
                }
                // New logic
                if (DRM_PROCESS_NAMES_SET.contains(input.substringAfterLast('/'))) {
                    // match
                }
            }
        }

        val oldTime = measureNanoTime {
            repeat(iterations) {
                for (input in TEST_INPUTS) {
                    for (target in DRM_PROCESS_NAMES_LIST) {
                        if (input == target || input.endsWith("/$target")) {
                            break
                        }
                    }
                }
            }
        }

        val newTime = measureNanoTime {
            repeat(iterations) {
                for (input in TEST_INPUTS) {
                    if (DRM_PROCESS_NAMES_SET.contains(input.substringAfterLast('/'))) {
                        // match
                    }
                }
            }
        }

        println("BASELINE_OLD_LOGIC_NS: $oldTime")
        println("OPTIMIZED_NEW_LOGIC_NS: $newTime")
        val speedup = (oldTime.toDouble() / newTime.toDouble())
        println("SPEEDUP: ${String.format("%.2f", speedup)}x")

        // Output for automated parsing if needed
        System.err.println("PERF_RESULTS: old=$oldTime ns, new=$newTime ns, speedup=$speedup")
    }
}
