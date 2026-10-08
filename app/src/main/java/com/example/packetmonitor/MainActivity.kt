package com.example.packetmonitor

import android.content.Intent
import android.graphics.Typeface
import android.net.TrafficStats
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.view.ViewGroup
import android.widget.*
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    private val h = Handler(Looper.getMainLooper())
    private lateinit var stats: TextView
    private lateinit var adapter: BaseAdapter
    private val rows = ArrayList<Pkt>()
    private var lastRx = 0L; private var lastTx = 0L
    private var lastRxP = 0L; private var lastTxP = 0L
    private val W = 0xFFEEEEEE.toInt()

    private fun dp(x: Int) = (x * resources.displayMetrics.density).toInt()

    private fun cell(t: String, w: Int, color: Int, bold: Boolean = false) = TextView(this).apply {
        text = t; textSize = 11f; setTextColor(color); maxLines = 1
        setTypeface(Typeface.MONOSPACE, if (bold) Typeface.BOLD else Typeface.NORMAL)
        layoutParams = LinearLayout.LayoutParams(dp(w), ViewGroup.LayoutParams.WRAP_CONTENT)
    }

    private fun rowOf(vararg c: TextView) = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        setPadding(dp(6), dp(5), dp(6), dp(5))
        c.forEach { addView(it) }
    }

    private val ticker = object : Runnable {
        override fun run() {
            val rx = TrafficStats.getTotalRxBytes(); val tx = TrafficStats.getTotalTxBytes()
            val rxP = TrafficStats.getTotalRxPackets(); val txP = TrafficStats.getTotalTxPackets()
            stats.text = "⬇ Received: $rx B  (+${rx - lastRx} B/s)\n" +
                "⬆ Sent: $tx B  (+${tx - lastTx} B/s)\n" +
                "Packets in: $rxP  (+${rxP - lastRxP}/s)\n" +
                "Packets out: $txP  (+${txP - lastTxP}/s)\n" +
                "Capture: ${if (CaptureVpnService.running) "ON" else "OFF"}  |  Rows: ${rows.size}"
            lastRx = rx; lastTx = tx; lastRxP = rxP; lastTxP = txP
            rows.clear()
            synchronized(CaptureVpnService.log) { rows.addAll(CaptureVpnService.log) }
            adapter.notifyDataSetChanged()
            h.postDelayed(this, 1000)
        }
    }

    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        val bg = 0xFF121212.toInt()

        stats = TextView(this).apply {
            textSize = 13f; setTextColor(W); typeface = Typeface.MONOSPACE
            setBackgroundColor(0xFF1E2A38.toInt()); setPadding(dp(14), dp(12), dp(14), dp(12))
        }

        val start = Button(this).apply {
            text = "▶ START"
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
            setOnClickListener {
                val i = VpnService.prepare(this@MainActivity)
                if (i != null) startActivityForResult(i, 1) else startVpn()
            }
        }
        val stop = Button(this).apply {
            text = "■ STOP"
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
            setOnClickListener { CaptureVpnService.running = false }
        }
        val clear = Button(this).apply {
            text = "CLEAR"
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
            setOnClickListener { CaptureVpnService.log.clear() }
        }
        val buttons = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            addView(start); addView(stop); addView(clear)
        }

        val header = rowOf(
            cell("Date", 80, 0xFFFFD54F.toInt(), true), cell("Time.ms", 95, 0xFFFFD54F.toInt(), true),
            cell("Size", 55, 0xFFFFD54F.toInt(), true), cell("Source IP:Port", 150, 0xFFFFD54F.toInt(), true),
            cell("Dest IP:Port", 150, 0xFFFFD54F.toInt(), true), cell("Proto", 50, 0xFFFFD54F.toInt(), true)
        ).apply { setBackgroundColor(0xFF2C2C2C.toInt()) }

        adapter = object : BaseAdapter() {
            override fun getCount() = rows.size
            override fun getItem(i: Int) = rows[i]
            override fun getItemId(i: Int) = i.toLong()
            override fun getView(i: Int, v: View?, p: ViewGroup?): View {
                val r = rows[i]
                val pc = when (r.proto) {
                    "TCP" -> 0xFF64B5F6.toInt(); "UDP" -> 0xFF81C784.toInt(); else -> 0xFFBDBDBD.toInt()
                }
                return rowOf(
                    cell(r.date, 80, W), cell(r.time, 95, W), cell("${r.size} B", 55, W),
                    cell(r.src, 150, W), cell(r.dst, 150, W), cell(r.proto, 50, pc, true)
                ).apply { setBackgroundColor(if (i % 2 == 0) 0xFF1A1A1A.toInt() else bg) }
            }
        }
        val list = ListView(this).apply {
            this.adapter = this@MainActivity.adapter
            divider = null
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f)
        }
        val table = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = ViewGroup.LayoutParams(dp(600), ViewGroup.LayoutParams.MATCH_PARENT)
            addView(header); addView(list)
        }
        val hscroll = HorizontalScrollView(this).apply {
            isFillViewport = true
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f)
            addView(table)
        }

        setContentView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(bg)
            addView(stats); addView(buttons); addView(hscroll)
        })

        lastRx = TrafficStats.getTotalRxBytes(); lastTx = TrafficStats.getTotalTxBytes()
        lastRxP = TrafficStats.getTotalRxPackets(); lastTxP = TrafficStats.getTotalTxPackets()
        h.post(ticker)
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

    override fun onDestroy() { h.removeCallbacks(ticker); super.onDestroy() }
}
