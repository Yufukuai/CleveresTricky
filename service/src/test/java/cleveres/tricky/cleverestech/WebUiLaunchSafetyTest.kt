package cleveres.tricky.cleverestech

import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File

class WebUiLaunchSafetyTest {

    private lateinit var actionScriptContent: String
    private lateinit var manifestContent: String
    private lateinit var networkSecurityConfigContent: String
    private lateinit var webServerContent: String
    private lateinit var webUiConfigContent: String

    @Before
    fun setup() {
        actionScriptContent = moduleTemplateFile("action.sh").readText()
        val workingDir = File(System.getProperty("user.dir")).absoluteFile
        manifestContent = (
            generateSequence(workingDir) { it.parentFile }
            .map { File(it, "service/src/main/AndroidManifest.xml") }
            .firstOrNull(File::exists)
            ?: error("Could not locate service/src/main/AndroidManifest.xml from ${workingDir.absolutePath}")
        ).readText()
        networkSecurityConfigContent = (
            generateSequence(workingDir) { it.parentFile }
            .map { File(it, "service/src/main/res/xml/network_security_config.xml") }
            .firstOrNull(File::exists)
            ?: error("Could not locate service/src/main/res/xml/network_security_config.xml from ${workingDir.absolutePath}")
        ).readText()
        webServerContent = serviceMainFile("WebServer.kt").readText()
        webUiConfigContent = serviceMainFile("WebUiConfig.kt").readText()
    }

    @Test
    fun testActionScriptUsesLoopbackIp() {
        assertTrue(
            "WebUI action script must use localhost to support IPv6 resolution",
            actionScriptContent.contains("localhost")
        )
    }

    @Test
    fun testActionScriptAddsNewTaskFlag() {
        assertTrue(
            "WebUI action script must add FLAG_ACTIVITY_NEW_TASK when launching ACTION_VIEW from shell context",
            actionScriptContent.contains("-f 0x10000000")
        )
    }

    @Test
    fun testActionScriptWaitsForReadiness() {
        assertTrue(
            "WebUI action script must wait for the loopback server before launching the browser",
            actionScriptContent.contains("Waiting for WebUI to listen") &&
                actionScriptContent.contains("toybox nc -z")
        )
    }

    @Test
    fun testActionScriptLogsIntentFailures() {
        assertTrue(
            "WebUI action script must log am start failures and missing browser resolution details",
            actionScriptContent.contains("START_OUTPUT=$(am start -W") &&
                actionScriptContent.contains("ActivityNotFoundException") &&
                actionScriptContent.contains("unable to resolve Intent")
        )
    }

    @Test
    fun testManifestUsesExplicitNetworkSecurityConfig() {
        assertTrue(
            "Manifest must reference an explicit network security config for localhost cleartext traffic",
            manifestContent.contains("android:networkSecurityConfig=\"@xml/network_security_config\"")
        )
    }

    @Test
    fun testNetworkSecurityConfigAllowsLocalhostCleartext() {
        assertTrue(
            "Network security config must allow cleartext loopback traffic for the local WebUI",
            networkSecurityConfigContent.contains("cleartextTrafficPermitted=\"true\"") &&
                networkSecurityConfigContent.contains("<domain includeSubdomains=\"true\">localhost</domain>")
        )
    }

    @Test
    fun testWebServerWaitsForListeningSocket() {
        assertTrue(
            "WebServer startup must actively wait for the loopback socket to accept connections before advertising the URL",
            webServerContent.contains("waitUntilListening") &&
                webServerContent.contains("Socket().use") &&
                webServerContent.contains("WEB_UI_LOOPBACK_HOST")
        )
    }

    @Test
    fun testWebUiConfigUsesLoopbackHost() {
        assertTrue(
            "WebUI config must use localhost instead of wildcard addresses",
            webUiConfigContent.contains("""WEB_UI_LOOPBACK_HOST = "localhost"""")
        )
    }

    @Test
    fun testWebServerSourceContainsNoNonAsciiCharacters() {
        val violations = webServerContent.lines().mapIndexedNotNull { index, line ->
            val col = line.indexOfFirst { it.code > 127 }
            if (col >= 0) "Line ${index + 1}, col ${col + 1}: U+${line[col].code.toString(16).uppercase().padStart(4, '0')} (${line[col]})"
            else null
        }
        assertTrue(
            "WebUI source must use only ASCII characters — no emojis or Unicode symbols allowed.\nViolations:\n${violations.joinToString("\n")}",
            violations.isEmpty()
        )
    }
}
