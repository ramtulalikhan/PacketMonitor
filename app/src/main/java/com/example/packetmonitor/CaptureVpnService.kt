package com.example.packetmonitor

import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.text.SimpleDateFormat
import java.util.*

class CaptureVpnService : VpnService() {
    companion object {
        @Volatile var running = false
        val log: MutableList<String> = Collections.synchronizedList(LinkedList())
    }

    private var tun: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: android.content.Intent?, flags: Int, startId: Int): Int {
        tun = Builder()
            .setSession("PacketMonitor")
            .addAddress("10.0.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .establish()

        Thread {
            val input = FileInputStream(tun!!.fileDescriptor)
            val buf = ByteArray(32767)
            val fmt = SimpleDateFormat("dd-MM-yyyy HH:mm:ss.SSS", Locale.US)
            while (running) {
                val len = input.read(buf)
                if (len > 20 && (buf[0].toInt() shr 4) == 4) {
                    val ihl = (buf[0].toInt() and 0x0F) * 4
                    val proto = buf[9].toInt() and 0xFF
                    val src = (12..15).joinToString(".") { (buf[it].toInt() and 0xFF).toString() }
                    val dst = (16..19).joinToString(".") { (buf[it].toInt() and 0xFF).toString() }
                    var sp = 0; var dp = 0
                    if ((proto == 6 || proto == 17) && len >= ihl + 4) {
                        sp = ((buf[ihl].toInt() and 0xFF) shl 8) or (buf[ihl + 1].toInt() and 0xFF)
                        dp = ((buf[ihl + 2].toInt() and 0xFF) shl 8) or (buf[ihl + 3].toInt() and 0xFF)
                    }
                    val p = when (proto) { 6 -> "TCP"; 17 -> "UDP"; 1 -> "ICMP"; else -> "$proto" }
                    log.add(0, "${fmt.format(Date())} | $len B | $src:$sp -> $dst:$dp | $p")
                    while (log.size > 100) log.removeAt(log.size - 1)
                }
            }
            tun?.close()
            stopSelf()
        }.start()
        return START_NOT_STICKY
    }

    override fun onDestroy() { running = false; tun?.close(); super.onDestroy() }
}
