package com.example.packetmonitor

import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.*
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.ConcurrentHashMap

data class Pkt(val date: String, val time: String, val size: Int, val src: String, val dst: String, val proto: String)

class CaptureVpnService : VpnService() {
    companion object {
        @Volatile var running = false
        val log: MutableList<Pkt> = Collections.synchronizedList(LinkedList())
    }

    private var tun: ParcelFileDescriptor? = null
    private lateinit var out: FileOutputStream
    private val udp = ConcurrentHashMap<String, DatagramSocket>()
    private val df = SimpleDateFormat("dd-MM-yyyy", Locale.US)
    private val tf = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)

    private fun u16(b: ByteArray, o: Int) = ((b[o].toInt() and 0xFF) shl 8) or (b[o + 1].toInt() and 0xFF)
    private fun ip(b: ByteArray, o: Int) = (o until o + 4).joinToString(".") { (b[it].toInt() and 0xFF).toString() }

    @Synchronized
    private fun addLog(s: String, sp: Int, d: String, dp: Int, size: Int, proto: String) {
        val now = Date()
        log.add(0, Pkt(df.format(now), tf.format(now), size, "$s:$sp", "$d:$dp", proto))
        while (log.size > 100) log.removeAt(log.size - 1)
    }

    private fun checksum(b: ByteArray, len: Int): Int {
        var sum = 0
        var i = 0
        while (i < len) { sum += u16(b, i); i += 2 }
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        return sum.inv() and 0xFFFF
    }

    // Reply packet (server -> phone) banao aur TUN mein likho
    private fun writeUdp(phoneIp: ByteArray, phonePort: Int, srvIp: ByteArray, srvPort: Int, data: ByteArray, n: Int) {
        val total = 28 + n
        val p = ByteArray(total)
        p[0] = 0x45; p[2] = (total shr 8).toByte(); p[3] = total.toByte()
        p[6] = 0x40; p[8] = 64; p[9] = 17
        System.arraycopy(srvIp, 0, p, 12, 4)
        System.arraycopy(phoneIp, 0, p, 16, 4)
        val c = checksum(p, 20)
        p[10] = (c shr 8).toByte(); p[11] = c.toByte()
        p[20] = (srvPort shr 8).toByte(); p[21] = srvPort.toByte()
        p[22] = (phonePort shr 8).toByte(); p[23] = phonePort.toByte()
        val ul = 8 + n
        p[24] = (ul shr 8).toByte(); p[25] = ul.toByte()
        System.arraycopy(data, 0, p, 28, n)
        synchronized(out) { out.write(p) }
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
            protect(sock)          // zaroori: ye socket VPN se bahar jayega
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

    override fun onStartCommand(intent: android.content.Intent?, flags: Int, startId: Int): Int {
        tun = Builder()
            .setSession("PacketMonitor")
            .addAddress("10.0.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("8.8.8.8")
            .establish()
        out = FileOutputStream(tun!!.fileDescriptor)

        Thread {
            val input = FileInputStream(tun!!.fileDescriptor)
            val buf = ByteArray(32767)
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
                }
            }
            tun?.close()
            stopSelf()
        }.start()
        return START_NOT_STICKY
    }

    override fun onDestroy() { running = false; tun?.close(); super.onDestroy() }
}
