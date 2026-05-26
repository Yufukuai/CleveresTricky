package cleveres.tricky.cleverestech.util

import org.junit.Test
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.system.measureTimeMillis

class KeyboxFetcherPerfTest {

    @Test
    fun benchmarkFetchMultipleLinks() = runBlocking {
        val numLinks = 10
        val fakeNetwork = object : KeyboxFetcher.NetworkClient {
            override suspend fun fetch(url: String): String? {
                kotlinx.coroutines.delay(100) // Simulate network latency correctly for async!
                if (url == "http://example.com/pool.txt") {
                    val sb = StringBuilder()
                    for (i in 1..numLinks) {
                        sb.append("http://example.com/link$i.xml\n")
                    }
                    return sb.toString()
                }
                return "<keybox></keybox>"
            }
        }
        val fetcher = KeyboxFetcher(fakeNetwork)

        val time = measureTimeMillis {
            fetcher.harvest("http://example.com/pool.txt", File("/tmp"))
        }
        println("Benchmark time: $time ms")
    }
}
