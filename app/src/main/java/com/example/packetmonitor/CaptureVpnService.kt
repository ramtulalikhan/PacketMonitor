package com.example.packetmonitor

import android.content.Context
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.*
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.atomic.AtomicLong

data class Pkt(
    val date: String, val time: String, val size: Int,
    val src: String, val dst: String, val proto: String,
    val app: String, val domain: String, val out: Boolean
)

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
        val dns = ConcurrentHashMap<String, String>()
        val ipStats = ConcurrentHashMap<String, LongArray>()   // [sent, received, packets]
        val appStats = ConcurrentHashMap<String, LongArray>()
        val bytesIn = AtomicLong(); val bytesOut = AtomicLong()
        val pktIn = AtomicLong(); val pktOut = AtomicLong()
        fun clearAll() { log.clear(); ipStats.clear(); appStats.clear() }
    }

    private val M = 0xFFFFFFFFL
    private var tun: ParcelFileDescriptor? = null
    private lateinit var out: FileOutputStream
    private val udp = ConcurrentHashMap<String, DatagramSocket>()
    private val tcp = ConcurrentHashMap<String, Conn>()
    private val appCache = ConcurrentHashMap<String, String>()
    private val uidName = ConcurrentHashMap<Int, String>()
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

    // ---------------- App name ----------------
    private fun labelOf(uid: Int): String = uidName.getOrPut(uid) {
        try {
            val pk = packageManager.getPackagesForUid(uid)
            if (pk.isNullOrEmpty()) "uid $uid"
            else packageManager.getApplicationLabel(packageManager.getApplicationInfo(pk[0], 0)).toString()
        } catch (e: Exception) { "uid $uid" }
    }

    private fun appName(proto: Int, phonePort: Int, remIp: String, remPort: Int): String {
        if (proto != 6 && proto != 17) return "-"
        if (Build.VERSION.SDK_INT < 29) return "?"
        val key = "$proto:$phonePort:$remIp:$remPort"
        appCache[key]?.let { return it }
        var name = "?"
        try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val uid = cm.getConnectionOwnerUid(
                proto,
                InetSocketAddress(InetAddress.getByName("10.0.0.2"), phonePort),
                InetSocketAddress(InetAddress.getByName(remIp), remPort)
            )
            if (uid >= 0) name = labelOf(uid)
        } catch (e: Exception) { }
        if (appCache.size > 3000) appCache.clear()
        appCache[key] = name
        return name
    }

    // ---------------- DNS ----------------
    private fun readName(b: ByteArray, start: Int, n: Int): Pair<String, Int> {
        val sb = StringBuilder(); var o = start; var end = -1; var hops = 0
        while (o < n && hops < 20) {
            val l = b[o].toInt() and 0xFF
            if (l == 0) { if (end < 0) end = o + 1; break }
            if ((l and 0xC0) == 0xC0) {
                if (o + 1 >= n) break
                if (end < 0) end = o + 2
                o = ((l and 0x3F) shl 8) or (b[o + 1].toInt() and 0xFF)
                hops++; continue
            }
            if (o + 1 + l > n) break
            if (sb.isNotEmpty()) sb.append('.')
            sb.append(String(b, o + 1, l, Charsets.US_ASCII))
            o += 1 + l
        }
        return Pair(sb.toString(), if (end < 0) n else end)
    }

    private fun parseDns(d: ByteArray, n: Int): String? {
        try {
            if (n < 12) return null
            val qd = u16(d, 4); val an = u16(d, 6)
            var o = 12; var qname = ""
            for (i in 0 until qd) {
                val r = readName(d, o, n)
                if (i == 0) qname = r.first
                o = r.second + 4
            }
            for (i in 0 until an) {
                if (o >= n) break
                o = readName(d, o, n).second
                if (o + 10 > n) break
                val type = u16(d, o); val rdlen = u16(d, o + 8)
                o += 10
                if (type == 1 && rdlen == 4 && o + 4 <= n && qname.isNotEmpty()) dns[ip(d, o)] = qname
                o += rdlen
            }
            return qname
        } catch (e: Exception) { return null }
    }

    // ---------------- Logging ----------------
    private fun logPkt(outbound: Boolean, proto: Int, phonePort: Int, remIp: String, remPort: Int, size: Int, dnsName: String? = null) {
        val app = appName(proto, phonePort, remIp, remPort)
        synchronized(this) {
            val now = Date()
            val domain = dnsName ?: dns[remIp] ?: ""
            val phone = "10.0.0.2:$phonePort"
            val rem = "$remIp:$remPort"
            val pn = when (proto) { 6 -> "TCP"; 17 -> "UDP"; 1 -> "ICMP"; else -> "$proto" }
            log.add(0, Pkt(df.format(now), tf.format(now), size,
                if (outbound) phone else rem, if (outbound) rem else phone, pn, app, domain, outbound))
            while (log.size > 5000) log.removeAt(log.size - 1)
            val i = if (outbound) 0 else 1
            if (outbound) { bytesOut.addAndGet(size.toLong()); pktOut.incrementAndGet() }
            else { bytesIn.addAndGet(size.toLong()); pktIn.incrementAndGet() }
            val a: LongArray = ipStats.getOrPut(remIp) { LongArray(3) }
            a[i] = a[i] + size.toLong()
            a[2] = a[2] + 1L
            val b: LongArray = appStats.getOrPut(app) { LongArray(3) }
            b[i] = b[i] + size.toLong()
            b[2] = b[2] + 1L
        }
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
        val dn = if (srvPort == 53) parseDns(data, n) else null
        logPkt(false, 17, phonePort, ip(srvIp, 0), srvPort, total, dn)
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
        logPkt(false, 6, c.phonePort, ip(c.srvIp, 0), c.srvPort, total)
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
                protect(s)
                s.connect(InetSocketAddress(InetAddress.getByAddress(c.srvIp), c.srvPort), 10000)
                s.tcpNoDelay = true
                c.sock = s
                synchronized(c) {
                    writeTcp(c, 0x12, c.sndNxt, c.rcvNxt, null, 0, true)
                    c.sndNxt = (c.sndNxt + 1) and M
                    c.peerAck = c.sndNxt
                }
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
                val inp = s.getInputStream()
                val rb = ByteArray(1400)
                while (!c.closed) {
                    val n = inp.read(rb)
                    if (n < 0) break
                    while (!c.closed && ((c.sndNxt - c.peerAck) and M) >= 32768) Thread.sleep(2)
                    if (c.closed) break
                    synchronized(c) {
                        writeTcp(c, 0x18, c.sndNxt, c.rcvNxt, rb, n)
                        c.sndNxt = (c.sndNxt + n) and M
                    }
                }
                if (!c.closed) {
                    synchronized(c) {
                        writeTcp(c, 0x11, c.sndNxt, c.rcvNxt, null, 0)
                        c.sndNxt = (c.sndNxt + 1) and M
                    }
                    c.srvFin = true
                    if (c.phoneFin) closeConn(key, c)
                }
            } catch (e: Exception) {
                if (!c.closed) {
                    synchronized(c) { writeTcp(c, 0x14, c.sndNxt, c.rcvNxt, null, 0) }
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

        if ((flags and 4) != 0) { if (c != null) closeConn(key, c); return }
        if ((flags and 2) != 0) {
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
        if ((flags and 16) != 0) c.peerAck = ack

        var needAck = false
        if (payLen > 0) {
            needAck = true
            if (seq == c.rcvNxt) {
                c.rcvNxt = (c.rcvNxt + payLen) and M
                c.outq.put(buf.copyOfRange(ihl + doff, ihl + doff + payLen))
            }
        }
        if ((flags and 1) != 0 && !c.phoneFin && ((seq + payLen) and M) == c.rcvNxt) {
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
                        var dn: String? = null
                        if (proto == 17 && dp == 53 && len > ihl + 21) dn = readName(buf, ihl + 20, len).first
                        logPkt(true, proto, sp, ip(buf, 16), dp, len, dn)
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
