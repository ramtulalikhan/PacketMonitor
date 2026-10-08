package com.example.packetmonitor

import android.content.Intent
import android.net.TrafficStats
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    private val handler = Handler(Looper.getMainLooper())
    private lateinit var tv: TextView
    private lateinit var logTv: TextView
    private var lastRx = 0L; private var lastTx = 0L
    private var lastRxP = 0L; private var lastTxP = 0L

    private val ticker = object : Runnable {
        override fun run() {
            val rx = TrafficStats.getTotalRxBytes()
            val tx = TrafficStats.getTotalTxBytes()
            val rxP = TrafficStats.getTotalRxPackets()
            val txP = TrafficStats.getTotalTxPackets()
            val appRx = TrafficStats.getUidRxBytes(android.os.Process.myUid())

            tv.text = "Total received: $rx B (+${rx - lastRx} B/s)\n" +
                "Total sent: $tx B (+${tx - lastTx} B/s)\n" +
                "Packets in: $rxP (+${rxP - lastRxP}/s)\n" +
                "Packets out: $txP (+${txP - lastTxP}/s)\n" +
                "Is app ka received: $appRx B"

            lastRx = rx; lastTx = tx; lastRxP = rxP; lastTxP = txP
            logTv.text = CaptureVpnService.log.joinToString("\n")
            handler.postDelayed(this, 1000)
        }
    }

    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        tv = TextView(this).apply { setPadding(32, 32, 32, 16) }
        logTv = TextView(this).apply { setPadding(32, 16, 32, 32); textSize = 10f }
        val btn = Button(this).apply {
            text = "Start packet capture (VPN)"
            setOnClickListener {
                val i = VpnService.prepare(this@MainActivity)
                if (i != null) startActivityForResult(i, 1) else startVpn()
            }
        }
        val stop = Button(this).apply {
            text = "Stop capture"
            setOnClickListener { CaptureVpnService.running = false }
        }
        setContentView(ScrollView(this).apply {
            addView(LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.VERTICAL
                addView(tv); addView(btn); addView(stop); addView(logTv)
            })
        })
        lastRx = TrafficStats.getTotalRxBytes(); lastTx = TrafficStats.getTotalTxBytes()
        lastRxP = TrafficStats.getTotalRxPackets(); lastTxP = TrafficStats.getTotalTxPackets()
        handler.post(ticker)
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(r: Int, c: Int, d: Intent?) {
        super.onActivityResult(r, c, d)
        if (r == 1 && c == RESULT_OK) startVpn()
    }

    private fun startVpn() {
        CaptureVpnService.running = true
        startService(Intent(this, CaptureVpnService::class.java))
    }

    override fun onDestroy() { handler.removeCallbacks(ticker); super.onDestroy() }
}
