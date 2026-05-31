package cleveres.tricky.cleverestech

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Tests that validate WebUI code correctness, mobile UX, and accessibility.
 *
 * These tests scan WebServer.kt for patterns required for a functional,
 * accessible, and mobile-friendly web interface.
 */
class WebUiSafetyTest {

    private lateinit var webServerContent: String

    @Before
    fun setup() {
        webServerContent = serviceMainFile("WebServer.kt").readText()
    }

    // ================================
    // Mobile UX fundamentals
    // ================================

    @Test
    fun testHasViewportMeta() {
        assertTrue(
            "HTML must have viewport meta tag for mobile rendering",
            webServerContent.contains("name=\"viewport\"")
        )
    }

    @Test
    fun testHasMobileMediaQuery() {
        assertTrue(
            "CSS must have a media query for mobile screens (max-width: 600px)",
            webServerContent.contains("@media screen and (max-width: 600px)")
        )
    }

    @Test
    fun testMobileGridStacking() {
        assertTrue(
            "grid-2 must stack to single column on mobile for usability",
            webServerContent.contains(".grid-2 { grid-template-columns: 1fr; }")
        )
    }

    @Test
    fun testTouchFriendlyButtons() {
        assertTrue(
            "Buttons must have min-height: 44px for touch-friendly interaction (Apple HIG minimum)",
            webServerContent.contains("min-height: 44px")
        )
    }

    @Test
    fun testTouchFriendlyInputs() {
        assertTrue(
            "Text inputs must have min-height: 44px for touch-friendly interaction",
            webServerContent.contains("min-height: 44px")
        )
    }

    @Test
    fun testResponsiveTable() {
        assertTrue(
            "Tables must be responsive on mobile (convert to card layout)",
            webServerContent.contains("responsive-table")
        )
    }

    // ================================
    // Tab navigation completeness
    // ================================

    @Test
    fun testAllTabsInNavigationArray() {
        val tabIds = listOf("dashboard", "spoof", "apps", "keys", "info", "guide", "editor", "donate")
        for (tabId in tabIds) {
            assertTrue(
                "Tab '$tabId' must be present in handleTabNavigation tabs array for keyboard navigation",
                webServerContent.contains("'$tabId'") && webServerContent.contains("id=\"tab_$tabId\"")
            )
        }
    }

    @Test
    fun testInfoTabInKeyboardNavigation() {
        assertTrue(
            "handleTabNavigation must include 'info' tab for complete keyboard navigation",
            webServerContent.contains("'dashboard', 'spoof', 'apps', 'keys', 'info', 'guide', 'editor', 'donate'")
        )
    }

    // ================================
    // Accessibility
    // ================================

    @Test
    fun testTabsHaveAriaRoles() {
        assertTrue(
            "Tabs container must have role='tablist'",
            webServerContent.contains("role=\"tablist\"")
        )
        assertTrue(
            "Individual tabs must have role='tab'",
            webServerContent.contains("role=\"tab\"")
        )
    }

    @Test
    fun testContentPanelsHaveAriaRoles() {
        assertTrue(
            "Content panels must have role='tabpanel'",
            webServerContent.contains("role=\"tabpanel\"")
        )
    }

    @Test
    fun testIslandHasAriaLive() {
        assertTrue(
            "Notification island must have aria-live for screen readers",
            webServerContent.contains("aria-live=\"polite\"")
        )
    }

    // ================================
    // Security
    // ================================

    @Test
    fun testTokenBasedAuth() {
        assertTrue(
            "WebUI must use token-based authentication",
            webServerContent.contains("X-Auth-Token")
        )
    }

    @Test
    fun testNotificationEscapesHtml() {
        assertTrue(
            "Notification function must escape HTML to prevent XSS",
            webServerContent.contains("div.innerText = msg") && webServerContent.contains("div.innerHTML")
        )
    }

    @Test
    fun testLocalhostOnlyBinding() {
        assertTrue(
            "WebServer must bind to localhost only (127.0.0.1) for security",
            webServerContent.contains("127.0.0.1") || webServerContent.contains("localhost")
        )
    }

    // ================================
    // Toggle handler correctness
    // ================================

    @Test
    fun testResourceToggleHandlerEscaping() {
        assertFalse(
            "Resource table toggle onchange handler must NOT have broken string escaping (\\' + f.id + \\')",
            webServerContent.contains("""onchange="toggle(\' + f.id + \')")""")
        )
    }

    @Test
    fun testResourceToggleHandlerCorrect() {
        assertTrue(
            "Resource table toggle onchange handler must properly interpolate f.id",
            webServerContent.contains("toggle(\\'' + f.id + '\\'")
        )
    }

    // ================================
    // IMEI validation in frontend
    // ================================

    @Test
    fun testFrontendHasLuhnValidation() {
        assertTrue(
            "Frontend must validate IMEI with Luhn algorithm",
            webServerContent.contains("sum % 10") && webServerContent.contains("luhn")
        )
    }

    @Test
    fun testFrontendHasImsiValidation() {
        assertTrue(
            "Frontend must validate IMSI format (15 digits)",
            webServerContent.contains("'imsi'") && webServerContent.contains("15 digits")
        )
    }

    @Test
    fun testFrontendHasMacValidation() {
        assertTrue(
            "Frontend must validate MAC address format",
            webServerContent.contains("'mac'") && webServerContent.contains("XX:XX:XX")
        )
    }
}
