package com.example.packetmonitor

import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.*
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingQueue

data class Pkt(val date: String, val time: String, val size: Int, val src: String, val dst: String, val proto: String)

class Conn(
    val phoneIp: ByteArray, val phonePort: Int,
    val srvIp: ByteArray, val srvPort: Int,
    var rcvNxt: Long, var sndNxt: Long
) {
    @Volatile var sock: Socket? = null
    @Volatile var peerAck = 0L
    @Volatile var closed = false
    @Volatile var srvFin = false
    @Volatile var phoneFin = false
    val outq = LinkedBlockingQueue<ByteArray>()
}

class CaptureVpnService : VpnService() {
    companion object {
        @Volatile var running = false
        val log: MutableList<Pkt> = Collections.synchronizedList(LinkedList())
    }

    private val M = 0xFFFFFFFFL
    private var tun: ParcelFileDescriptor? = null
    private lateinit var out: FileOutputStream
    private val udp = ConcurrentHashMap<String, DatagramSocket>()
    private val tcp = ConcurrentHashMap<String, Conn>()
    private val df = SimpleDateFormat("dd-MM-yyyy", Locale.US)
    private val tf = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)

    private fun u16(b: ByteArray, o: Int) = ((b[o].toInt() and 0xFF) shl 8) or (b[o + 1].toInt() and 0xFF)
    private fun u32(b: ByteArray, o: Int): Long =
        ((b[o].toLong() and 0xFF) shl 24) or ((b[o + 1].toLong() and 0xFF) shl 16) or
        ((b[o + 2].toLong() and 0xFF) shl 8) or (b[o + 3].toLong() and 0xFF)
    private fun put16(b: ByteArray, o: Int, v: Int) { b[o] = (v shr 8).toByte(); b[o + 1] = v.toByte() }
    private fun put32(b: ByteArray, o: Int, v: Long) {
        b[o] = (v shr 24).toByte(); b[o + 1] = (v shr 16).toByte(); b[o + 2] = (v shr 8).toByte(); b[o + 3] = v.toByte()
    }
    private fun ip(b: ByteArray, o: Int) = (o until o + 4).joinToString(".") { (b[it].toInt() and 0xFF).toString() }

    private fun sum(b: ByteArray, off: Int, len: Int, init: Int = 0): Int {
        var s = init; var i = off; val end = off + len
        while (i + 1 < end) { s += ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF); i += 2 }
        if (i < end) s += (b[i].toInt() and 0xFF) shl 8
        return s
    }
    private fun fold(s0: Int): Int {
        var s = s0
        while (s ushr 16 != 0) s = (s and 0xFFFF) + (s ushr 16)
        return s.inv() and 0xFFFF
    }

    @Synchronized
    private fun addLog(s: String, sp: Int, d: String, dp: Int, size: Int, proto: String) {
        val now = Date()
        log.add(0, Pkt(df.format(now), tf.format(now), size, "$s:$sp", "$d:$dp", proto))
        while (log.size > 200) log.removeAt(log.size - 1)
    }

    // ---------------- UDP ----------------
    private fun writeUdp(phoneIp: ByteArray, phonePort: Int, srvIp: ByteArray, srvPort: Int, data: ByteArray, n: Int) {
        val total = 28 + n
        val p = ByteArray(total)
        p[0] = 0x45; put16(p, 2, total); p[6] = 0x40; p[8] = 64; p[9] = 17
        System.arraycopy(srvIp, 0, p, 12, 4)
        System.arraycopy(phoneIp, 0, p, 16, 4)
        put16(p, 10, fold(sum(p, 0, 20)))
        put16(p, 20, srvPort); put16(p, 22, phonePort); put16(p, 24, 8 + n)
        System.arraycopy(data, 0, p, 28, n)
        try { synchronized(out) { out.write(p) } } catch (e: Exception) { return }
        addLog(ip(srvIp, 0), srvPort, ip(phoneIp, 0), phonePort, total, "UDP")
    }

    private fun handleUdp(buf: ByteArray, ihl: Int) {
        val total = u16(buf, 2)
        val sp = u16(buf, ihl); val dp = u16(buf, ihl + 2)
        val phoneIp = buf.copyOfRange(12, 16)
        val dstBytes = buf.copyOfRange(16, 20)
        val dst = InetAddress.getByAddress(dstBytes)
        val payload = buf.copyOfRange(ihl + 8, total)
        val key = "$sp>${dst.hostAddress}:$dp"
        var s = udp[key]
        if (s == null) {
            val sock = DatagramSocket()
            protect(sock)
            sock.soTimeout = 30000
            udp[key] = sock
            s = sock
            Thread {
                val rb = ByteArray(65535)
                try {
                    while (running) {
                        val pk = DatagramPacket(rb, rb.size)
                        sock.receive(pk)
                        writeUdp(phoneIp, sp, dstBytes, dp, rb, pk.length)
                    }
                } catch (e: Exception) { }
                sock.close(); udp.remove(key)
            }.start()
        }
        try { s.send(DatagramPacket(payload, payload.size, dst, dp)) } catch (e: Exception) { }
    }

    // ---------------- TCP ----------------
    // flags: FIN=1 SYN=2 RST=4 PSH=8 ACK=16
    private fun writeTcp(c: Conn, flags: Int, seq: Long, ack: Long, data: ByteArray?, n: Int, mss: Boolean = false) {
        val th = if (mss) 24 else 20
        val total = 20 + th + n
        val p = ByteArray(total)
        p[0] = 0x45; put16(p, 2, total); p[6] = 0x40; p[8] = 64; p[9] = 6
        System.arraycopy(c.srvIp, 0, p, 12, 4)
        System.arraycopy(c.phoneIp, 0, p, 16, 4)
        put16(p, 10, fold(sum(p, 0, 20)))
        put16(p, 20, c.srvPort); put16(p, 22, c.phonePort)
        put32(p, 24, seq); put32(p, 28, ack)
        p[32] = ((th / 4) shl 4).toByte()
        p[33] = flags.toByte()
        put16(p, 34, 65535)
        if (mss) { p[40] = 2; p[41] = 4; put16(p, 42, 1400) }
        if (n > 0 && data != null) System.arraycopy(data, 0, p, 20 + th, n)
        var s = sum(p, 12, 8)
        s += 6 + (total - 20)
        s = sum(p, 20, total - 20, s)
        put16(p, 36, fold(s))
        try { synchronized(out) { out.write(p) } } catch (e: Exception) { return }
        addLog(ip(c.srvIp, 0), c.srvPort, ip(c.phoneIp, 0), c.phonePort, total, "TCP")
    }

    private fun closeConn(key: String, c: Conn) {
        c.closed = true
        tcp.remove(key)
        try { c.sock?.close() } catch (e: Exception) { }
        c.outq.put(ByteArray(0))
    }

    private fun openTcp(key: String, c: Conn) {
        Thread {
            try {
                val s = Socket()
                s.bind(null)
                protect(s)                       // zaroori: VPN se bahar jaye
                s.connect(InetSocketAddress(InetAddress.getByAddress(c.srvIp), c.srvPort), 10000)
                s.tcpNoDelay = true
                c.sock = s
                synchronized(c) {
                    writeTcp(c, 0x12, c.sndNxt, c.rcvNxt, null, 0, true)   // SYN+ACK
                    c.sndNxt = (c.sndNxt + 1) and M
                    c.peerAck = c.sndNxt
                }
                // phone -> server writer
                Thread {
                    try {
                        val os = s.getOutputStream()
                        while (true) {
                            val d = c.outq.take()
                            if (d.isEmpty()) {
                                if (!c.closed) try { s.shutdownOutput() } catch (e: Exception) { }
                                break
                            }
                            os.write(d); os.flush()
                        }
                    } catch (e: Exception) { }
                }.start()
                // server -> phone reader
                val inp = s.getInputStream()
                val rb = ByteArray(1400)
                while (!c.closed) {
                    val n = inp.read(rb)
                    if (n < 0) break
                    while (!c.closed && ((c.sndNxt - c.peerAck) and M) >= 32768) Thread.sleep(2)
                    if (c.closed) break
                    synchronized(c) {
                        writeTcp(c, 0x18, c.sndNxt, c.rcvNxt, rb, n)       // PSH+ACK
                        c.sndNxt = (c.sndNxt + n) and M
                    }
                }
                if (!c.closed) {
                    synchronized(c) {
                        writeTcp(c, 0x11, c.sndNxt, c.rcvNxt, null, 0)    // FIN+ACK
                        c.sndNxt = (c.sndNxt + 1) and M
                    }
                    c.srvFin = true
                    if (c.phoneFin) closeConn(key, c)
                }
            } catch (e: Exception) {
                if (!c.closed) {
                    synchronized(c) { writeTcp(c, 0x14, c.sndNxt, c.rcvNxt, null, 0) }  // RST+ACK
                    closeConn(key, c)
                }
            }
        }.start()
    }

    private fun handleTcp(buf: ByteArray, len: Int, ihl: Int) {
        if (len < ihl + 20) return
        val sp = u16(buf, ihl); val dp = u16(buf, ihl + 2)
        val seq = u32(buf, ihl + 4); val ack = u32(buf, ihl + 8)
        val doff = ((buf[ihl + 12].toInt() and 0xF0) shr 4) * 4
        val flags = buf[ihl + 13].toInt() and 0x3F
        val total = minOf(u16(buf, 2), len)
        val payLen = maxOf(0, total - ihl - doff)
        val key = "$sp>${ip(buf, 16)}:$dp"
        val c = tcp[key]

        if (flags and 4 != 0) { if (c != null) closeConn(key, c); return }
        if (flags and 2 != 0) {
            if (c == null) {
                val nc = Conn(
                    buf.copyOfRange(12, 16), sp, buf.copyOfRange(16, 20), dp,
                    (seq + 1) and M, System.nanoTime() and 0x7FFFFFFFL
                )
                tcp[key] = nc
                openTcp(key, nc)
            }
            return
        }
        if (c == null || c.sock == null) return
        if (flags and 16 != 0) c.peerAck = ack

        var needAck = false
        if (payLen > 0) {
            needAck = true
            if (seq == c.rcvNxt) {
                c.rcvNxt = (c.rcvNxt + payLen) and M
                c.outq.put(buf.copyOfRange(ihl + doff, ihl + doff + payLen))
            }
        }
        if (flags and 1 != 0 && !c.phoneFin && ((seq + payLen) and M) == c.rcvNxt) {
            c.rcvNxt = (c.rcvNxt + 1) and M
            c.phoneFin = true
            c.outq.put(ByteArray(0))
            needAck = true
        }
        if (needAck) synchronized(c) { writeTcp(c, 0x10, c.sndNxt, c.rcvNxt, null, 0) }
        if (c.phoneFin && c.srvFin) closeConn(key, c)
    }

    // ---------------- main ----------------
    override fun onStartCommand(intent: android.content.Intent?, flags: Int, startId: Int): Int {
        tun = Builder()
            .setSession("PacketMonitor")
            .setMtu(1500)
            .addAddress("10.0.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("8.8.8.8")
            .establish()
        out = FileOutputStream(tun!!.fileDescriptor)

        Thread {
            val input = FileInputStream(tun!!.fileDescriptor)
            val buf = ByteArray(32767)
            try {
                while (running) {
                    val len = input.read(buf)
                    if (len > 20 && (buf[0].toInt() shr 4) == 4) {
                        val ihl = (buf[0].toInt() and 0x0F) * 4
                        val proto = buf[9].toInt() and 0xFF
                        var sp = 0; var dp = 0
                        if ((proto == 6 || proto == 17) && len >= ihl + 4) { sp = u16(buf, ihl); dp = u16(buf, ihl + 2) }
                        val name = when (proto) { 6 -> "TCP"; 17 -> "UDP"; 1 -> "ICMP"; else -> "$proto" }
                        addLog(ip(buf, 12), sp, ip(buf, 16), dp, len, name)
                        if (proto == 17 && len >= ihl + 8) handleUdp(buf, ihl)
                        if (proto == 6) handleTcp(buf, len, ihl)
                    }
                }
            } catch (e: Exception) { }
            tcp.values.forEach { closeConn("", it) }
            tcp.clear()
            udp.values.forEach { try { it.close() } catch (e: Exception) { } }
            tun?.close()
            stopSelf()
        }.start()
        return START_NOT_STICKY
    }

    override fun onDestroy() { running = false; tun?.close(); super.onDestroy() }
}
