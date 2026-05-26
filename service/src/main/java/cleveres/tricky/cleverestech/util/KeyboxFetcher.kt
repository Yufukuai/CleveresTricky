package cleveres.tricky.cleverestech.util

import cleveres.tricky.cleverestech.Config
import cleveres.tricky.cleverestech.Logger
import cleveres.tricky.cleverestech.keystore.CertHack
import java.io.File
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.net.URI
import java.time.Duration
import kotlinx.coroutines.future.await
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.cert.Certificate
import java.util.Base64
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.coroutines.launch
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay

class KeyboxFetcher(private val networkClient: NetworkClient = DefaultNetworkClient(), private val dispatcher: kotlinx.coroutines.CoroutineDispatcher = kotlinx.coroutines.Dispatchers.IO) {

    interface NetworkClient {
        suspend fun fetch(url: String): String?
    }

    class DefaultNetworkClient : NetworkClient {
        private val httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15))
            .build()

        override suspend fun fetch(url: String): String? {
            return try {
                val request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(15))
                    .GET()
                    .build()

                val bodyHandler = HttpResponse.BodyHandler<String?> { responseInfo ->
                    val length = responseInfo.headers().firstValueAsLong("Content-Length").orElse(-1L)
                    if (length > MAX_FILE_SIZE) {
                        Logger.e("Fetcher: File too large ($length bytes)")
                        return@BodyHandler HttpResponse.BodySubscribers.replacing(null)
                    }

                    val stringSubscriber = HttpResponse.BodySubscribers.ofString(java.nio.charset.StandardCharsets.UTF_8)
                    var totalBytes = 0L

                    HttpResponse.BodySubscribers.fromSubscriber(
                        object : java.util.concurrent.Flow.Subscriber<MutableList<java.nio.ByteBuffer>> {
                            private var subscription: java.util.concurrent.Flow.Subscription? = null
                            private var overLimit = false

                            override fun onSubscribe(s: java.util.concurrent.Flow.Subscription) {
                                subscription = s
                                stringSubscriber.onSubscribe(s)
                            }

                            override fun onNext(item: MutableList<java.nio.ByteBuffer>) {
                                if (overLimit) return
                                for (buffer in item) {
                                    totalBytes += buffer.remaining()
                                }
                                if (totalBytes > MAX_FILE_SIZE) {
                                    Logger.e("Fetcher: File body exceeds size limit during download")
                                    overLimit = true
                                    subscription?.cancel()
                                    stringSubscriber.onError(java.io.IOException("Size limit exceeded"))
                                    return
                                }
                                stringSubscriber.onNext(item)
                            }

                            override fun onError(throwable: Throwable) {
                                stringSubscriber.onError(throwable)
                            }

                            override fun onComplete() {
                                if (!overLimit) {
                                    stringSubscriber.onComplete()
                                }
                            }
                        },
                        {
                            try {
                                stringSubscriber.body.toCompletableFuture().join()
                            } catch (e: Exception) {
                                null
                            }
                        }
                    )
                }

                val response = httpClient.sendAsync(request, bodyHandler).await()

                if (response.statusCode() == 200) {
                    response.body()
                } else {
                    Logger.e("Fetcher: Failed to fetch $url: ${response.statusCode()}")
                    null
                }
            } catch (e: Exception) {
                Logger.e("Fetcher: Exception fetching $url", e)
                null
            }
        }
    }

    suspend fun harvest(
        sourceUrl: String? = Config.keyboxSourceUrl,
        outputDir: File = Config.keyboxDirectory
    ) = withContext(dispatcher) {
        if (sourceUrl.isNullOrBlank()) {
            Logger.i("Fetcher: No source URL configured.")
            return@withContext
        }

        Logger.i("Fetcher: Starting harvest from $sourceUrl")

        try {
            val content = networkClient.fetch(sourceUrl) ?: return@withContext
            val keyboxes = ArrayList<CertHack.KeyBox>()

            if (content.trimStart().startsWith("<")) {
                keyboxes.addAll(CertHack.parseKeyboxXml(content.reader(), "harvested_direct.xml"))
            } else {
                coroutineScope {
                    val deferreds = content.lines()
                        .filter { it.isNotBlank() && !it.startsWith("#") }
                        .map { line ->
                            async {
                                val url = line.trim()
                                val xml = networkClient.fetch(url)
                                if (xml != null) {
                                    CertHack.parseKeyboxXml(xml.reader(), "harvested_${url.hashCode()}.xml")
                                } else {
                                    emptyList()
                                }
                            }
                        }

                    val results = deferreds.awaitAll()
                    results.forEach { keyboxes.addAll(it) }
                }
            }

            if (keyboxes.isEmpty()) {
                Logger.i("Fetcher: No keyboxes found.")
                return@withContext
            }

            val crl = KeyboxVerifier.fetchCrl()
            if (crl == null) {
                Logger.e("Fetcher: Failed to fetch CRL, aborting verification.")
                return@withContext
            }

            var added = 0
            val digest = MessageDigest.getInstance("SHA-256")
            for (kb in keyboxes) {
                if (KeyboxVerifier.verifyKeybox(kb, crl) == KeyboxVerifier.Status.VALID) {
                    saveKeybox(kb, outputDir, digest)
                    added++
                }
            }
            Logger.i("Fetcher: Finished. Added/Updated $added valid keyboxes.")

        } catch (e: Exception) {
            Logger.e("Fetcher: Error during harvest", e)
        }
    }

    @OptIn(ExperimentalStdlibApi::class)
    private val hexFormat = HexFormat { upperCase = false }

    @OptIn(ExperimentalStdlibApi::class)
    private fun saveKeybox(kb: CertHack.KeyBox, dir: File, digest: MessageDigest) {
        try {
            val pubEncoded = kb.keyPair.public.encoded
            val hash = digest.digest(pubEncoded)
            val hashStr = hash.toHexString(hexFormat).substring(0, 16)
            val fileName = "harvested_$hashStr.xml"
            val file = File(dir, fileName)

            if (file.exists()) return

            val sb = StringBuilder()
            sb.append("<?xml version=\"1.0\"?>\n")
            sb.append("<AndroidAttestation>\n")
            sb.append("    <NumberOfKeyboxes>1</NumberOfKeyboxes>\n")
            sb.append("    <Keybox DeviceID=\"Harvested\">\n")

            val algo = kb.keyPair.public.algorithm
            val algoStr = if (algo == "EC" || algo == "ECDSA") "ecdsa" else "rsa"

            sb.append("        <Key algorithm=\"$algoStr\">\n")
            sb.append("            <PrivateKey format=\"pem\">\n")
            sb.append(getPem(kb.keyPair.private))
            sb.append("            </PrivateKey>\n")

            sb.append("            <CertificateChain>\n")
            sb.append("                <NumberOfCertificates>${kb.certificates.size}</NumberOfCertificates>\n")
            for (cert in kb.certificates) {
                sb.append("                <Certificate format=\"pem\">\n")
                sb.append(getPem(cert))
                sb.append("                </Certificate>\n")
            }
            sb.append("            </CertificateChain>\n")
            sb.append("        </Key>\n")
            sb.append("    </Keybox>\n")
            sb.append("</AndroidAttestation>\n")

            SecureFile.writeText(file, sb.toString())
            Logger.i("Fetcher: Saved new keybox $fileName")
        } catch (e: Exception) {
            Logger.e("Fetcher: Failed to save keybox", e)
        }
    }

    private fun getPem(key: PrivateKey): String {
        val encoded = Base64.getEncoder().encodeToString(key.encoded)
        return "-----BEGIN PRIVATE KEY-----\n$encoded\n-----END PRIVATE KEY-----"
    }

    private fun getPem(cert: Certificate): String {
        val encoded = Base64.getEncoder().encodeToString(cert.encoded)
        return "-----BEGIN CERTIFICATE-----\n$encoded\n-----END CERTIFICATE-----"
    }

    companion object {
        private const val MAX_FILE_SIZE = 10 * 1024 * 1024 // 10MB

        fun schedule() {
            CoroutineScope(kotlinx.coroutines.Dispatchers.IO).launch {
                delay(TimeUnit.MINUTES.toMillis(5))
                while (true) {
                    try {
                        KeyboxFetcher().harvest()
                    } catch (e: Exception) {
                        Logger.e("Fetcher: Scheduled harvest failed", e)
                    }
                    delay(TimeUnit.MINUTES.toMillis(360))
                }
            }
        }
    }
}
