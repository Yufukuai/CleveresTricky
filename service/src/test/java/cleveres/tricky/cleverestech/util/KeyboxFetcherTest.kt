package cleveres.tricky.cleverestech.util

import cleveres.tricky.cleverestech.keystore.CertHack
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import kotlinx.coroutines.runBlocking
import org.mockito.MockedStatic
import org.mockito.Mockito
import java.io.File

class KeyboxFetcherTest {

    private lateinit var mockKeyboxVerifier: MockedStatic<KeyboxVerifier>
    private lateinit var mockCertHack: MockedStatic<CertHack>
    private lateinit var mockSecureFileOps: SecureFileOperations
    private var originalSecureFileImpl: SecureFileOperations = SecureFile.DefaultSecureFileOperations()

    @Before
    fun setup() {
        mockKeyboxVerifier = Mockito.mockStatic(KeyboxVerifier::class.java)
        mockCertHack = Mockito.mockStatic(CertHack::class.java)

        // Mock SecureFile.impl
        originalSecureFileImpl = SecureFile.impl
        mockSecureFileOps = Mockito.mock(SecureFileOperations::class.java)
        SecureFile.impl = mockSecureFileOps
    }

    @After
    fun tearDown() {
        // Ensure we handle case where setup failed
        if (::mockKeyboxVerifier.isInitialized) mockKeyboxVerifier.close()
        if (::mockCertHack.isInitialized) mockCertHack.close()
        SecureFile.impl = originalSecureFileImpl
    }

    class FakeNetworkClient(private val response: String?) : KeyboxFetcher.NetworkClient {
        var capturedUrl: String? = null
        override suspend fun fetch(url: String): String? {
            capturedUrl = url
            return response
        }
    }

    // Helper to avoid NPE with Kotlin non-null types and Mockito matchers
    private fun <T> anySafe(type: Class<T>): T {
        Mockito.any(type)
        @Suppress("UNCHECKED_CAST")
        if (type == File::class.java) return File("dummy") as T
        @Suppress("UNCHECKED_CAST")
        return Mockito.mock(type) // generic fallback
    }

    @Test
    fun `harvest fetches XML, verifies, and saves valid keybox`() = runBlocking {
        // Arrange
        val validXml = "<keybox>valid</keybox>"
        val sourceUrl = "http://example.com/pool.xml"
        val mockDir = File("/tmp/keyboxes")

        val fakeNetwork = FakeNetworkClient(validXml)

        // Mock Parsing
        val mockKeyBox = Mockito.mock(CertHack.KeyBox::class.java)
        val mockKp = Mockito.mock(java.security.KeyPair::class.java)
        val mockPub = Mockito.mock(java.security.PublicKey::class.java)
        Mockito.`when`(mockPub.encoded).thenReturn(byteArrayOf(1, 2, 3))
        Mockito.`when`(mockPub.algorithm).thenReturn("EC")
        Mockito.`when`(mockKp.public).thenReturn(mockPub)

        val mockPriv = Mockito.mock(java.security.PrivateKey::class.java)
        Mockito.`when`(mockPriv.encoded).thenReturn(byteArrayOf(4, 5, 6))
        Mockito.`when`(mockKp.private).thenReturn(mockPriv)

        Mockito.`when`(mockKeyBox.keyPair()).thenReturn(mockKp)
        Mockito.`when`(mockKeyBox.certificates()).thenReturn(emptyList())

        mockCertHack.`when`<List<CertHack.KeyBox>> { CertHack.parseKeyboxXml(Mockito.any(), Mockito.anyString()) }
            .thenReturn(listOf(mockKeyBox))

        // Mock CRL Fetch
        val mockCrl = setOf("bad_serial")
        mockKeyboxVerifier.`when`<Set<String>> { KeyboxVerifier.fetchCrl() }.thenReturn(mockCrl)

        // Mock Verification
        mockKeyboxVerifier.`when`<KeyboxVerifier.Status> { KeyboxVerifier.verifyKeybox(mockKeyBox, mockCrl) }
            .thenReturn(KeyboxVerifier.Status.VALID)

        // Act
        val fetcher = KeyboxFetcher(fakeNetwork, kotlinx.coroutines.Dispatchers.Unconfined)
        fetcher.harvest(sourceUrl, mockDir)

        // Assert
        assertEquals(sourceUrl, fakeNetwork.capturedUrl)
        // Use anySafe to satisfy Kotlin null-safety while registering Mockito matcher
        Mockito.verify(mockSecureFileOps).writeText(anySafe(File::class.java), Mockito.contains("<Keybox"))
    }

    @Test
    fun `harvest skips invalid keybox`() = runBlocking {
        // Arrange
        val xml = "<keybox>invalid</keybox>"
        val sourceUrl = "http://example.com/pool.xml"
        val mockDir = File("/tmp/keyboxes")

        val fakeNetwork = FakeNetworkClient(xml)

        val mockKeyBox = Mockito.mock(CertHack.KeyBox::class.java)
        mockCertHack.`when`<List<CertHack.KeyBox>> { CertHack.parseKeyboxXml(Mockito.any(), Mockito.anyString()) }
            .thenReturn(listOf(mockKeyBox))

        val mockCrl = emptySet<String>()
        mockKeyboxVerifier.`when`<Set<String>> { KeyboxVerifier.fetchCrl() }.thenReturn(mockCrl)

        mockKeyboxVerifier.`when`<KeyboxVerifier.Status> { KeyboxVerifier.verifyKeybox(mockKeyBox, mockCrl) }
            .thenReturn(KeyboxVerifier.Status.REVOKED)

        // Act
        val fetcher = KeyboxFetcher(fakeNetwork, kotlinx.coroutines.Dispatchers.Unconfined)
        fetcher.harvest(sourceUrl, mockDir)

        // Assert
        // Verify no write interactions
        Mockito.verifyNoInteractions(mockSecureFileOps)
    }
}
