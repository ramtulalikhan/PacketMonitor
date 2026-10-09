package com.example.packetmonitor

import android.content.ContentValues
import android.content.Intent
import android.graphics.Typeface
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.provider.MediaStore
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.view.ViewGroup
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import java.io.File

class MainActivity : AppCompatActivity() {
    private val h = Handler(Looper.getMainLooper())
    private lateinit var stats: TextView
    private lateinit var adapter: BaseAdapter
    private lateinit var header: LinearLayout
    private lateinit var table: LinearLayout
    private lateinit var search: EditText
    private lateinit var protoBtn: Button
    private val rows = ArrayList<List<String>>()
    private var mode = 0
    private var protoF = "ALL"
    private var lastBi = 0L; private var lastBo = 0L; private var lastPi = 0L; private var lastPo = 0L
    private val W = 0xFFEEEEEE.toInt()
    private val HC = 0xFFFFD54F.toInt()

    private val heads = arrayOf(
        arrayOf("Date", "Time.ms", "", "Size", "App", "Source IP:Port", "Dest IP:Port", "Domain", "Proto"),
        arrayOf("Server IP", "Domain", "Sent", "Received", "Packets"),
        arrayOf("App", "Sent", "Received", "Packets")
    )
    private val wids = arrayOf(
        intArrayOf(85, 95, 28, 60, 110, 150, 150, 170, 50),
        intArrayOf(140, 190, 90, 90, 70),
        intArrayOf(170, 100, 100, 80)
    )

    private fun dp(x: Int) = (x * resources.displayMetrics.density).toInt()

    private fun fmt(b: Long): String = when {
        b >= 1048576L -> String.format("%.1f MB", b / 1048576.0)
        b >= 1024L -> String.format("%.1f KB", b / 1024.0)
        else -> "$b B"
    }

    private fun cell(t: String, w: Int, color: Int, bold: Boolean = false) = TextView(this).apply {
        text = t; textSize = 11f; setTextColor(color); maxLines = 1
        setTypeface(Typeface.MONOSPACE, if (bold) Typeface.BOLD else Typeface.NORMAL)
        layoutParams = LinearLayout.LayoutParams(dp(w), ViewGroup.LayoutParams.WRAP_CONTENT)
    }

    private fun rowOf(c: List<TextView>) = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        setPadding(dp(6), dp(5), dp(6), dp(5))
        c.forEach { addView(it) }
    }

    private fun btn(t: String, f: () -> Unit) = Button(this).apply {
        text = t; textSize = 12f
        layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        setOnClickListener { f() }
    }

    private fun buildHeader() {
        header.removeAllViews()
        val hd = heads[mode]; val w = wids[mode]
        for (i in hd.indices) header.addView(cell(hd[i], w[i], HC, true))
        table.layoutParams = FrameLayout.LayoutParams(dp(w.sum() + 20), ViewGroup.LayoutParams.MATCH_PARENT)
    }

    private fun rebuild() {
        rows.clear()
        val q = search.text.toString().trim().lowercase()
        when (mode) {
            0 -> synchronized(CaptureVpnService.log) {
                for (r in CaptureVpnService.log) {
                    if (protoF != "ALL" && r.proto != protoF) continue
                    if (q.isNotEmpty() && !(r.src + " " + r.dst + " " + r.app + " " + r.domain).lowercase().contains(q)) continue
                    rows.add(listOf(r.date, r.time, if (r.out) "↑" else "↓", "${r.size}", r.app, r.src, r.dst, r.domain, r.proto))
                    if (rows.size >= 300) break
                }
            }
            1 -> {
                val items = CaptureVpnService.ipStats.entries.sortedByDescending { it.value[0] + it.value[1] }
                for (e in items) {
                    val v = e.value
                    val c = listOf(e.key, CaptureVpnService.dns[e.key] ?: "", fmt(v[0]), fmt(v[1]), "${v[2]}")
                    if (q.isEmpty() || c.joinToString(" ").lowercase().contains(q)) rows.add(c)
                    if (rows.size >= 300) break
                }
            }
            else -> {
                val items = CaptureVpnService.appStats.entries.sortedByDescending { it.value[0] + it.value[1] }
                for (e in items) {
                    val v = e.value
                    val c = listOf(e.key, fmt(v[0]), fmt(v[1]), "${v[2]}")
                    if (q.isEmpty() || c.joinToString(" ").lowercase().contains(q)) rows.add(c)
                }
            }
        }
    }

    private fun refresh() { rebuild(); adapter.notifyDataSetChanged() }

    private fun setMode(m: Int) { mode = m; buildHeader(); refresh() }

    private val ticker = object : Runnable {
        override fun run() {
            val bi = CaptureVpnService.bytesIn.get(); val bo = CaptureVpnService.bytesOut.get()
            val pi = CaptureVpnService.pktIn.get(); val po = CaptureVpnService.pktOut.get()
            stats.text = "⬇ Received: ${fmt(bi)}  (${fmt(maxOf(0L, bi - lastBi))}/s)\n" +
                "⬆ Sent: ${fmt(bo)}  (${fmt(maxOf(0L, bo - lastBo))}/s)\n" +
                "Packets in: $pi  (+${maxOf(0L, pi - lastPi)}/s)\n" +
                "Packets out: $po  (+${maxOf(0L, po - lastPo)}/s)\n" +
                "Capture: ${if (CaptureVpnService.running) "ON" else "OFF"} | Servers: ${CaptureVpnService.ipStats.size} | Apps: ${CaptureVpnService.appStats.size}"
            lastBi = bi; lastBo = bo; lastPi = pi; lastPo = po
            refresh()
            h.postDelayed(this, 1000)
        }
    }

    private fun q(s: String) = "\"" + s.replace("\"", "\"\"") + "\""

    private fun exportCsv() {
        val snap = synchronized(CaptureVpnService.log) { ArrayList(CaptureVpnService.log) }
        val sb = StringBuilder("Date,Time,Direction,Size,Source,Destination,Proto,App,Domain\n")
        for (r in snap.reversed()) {
            sb.append("${r.date},${r.time},${if (r.out) "OUT" else "IN"},${r.size},${r.src},${r.dst},${r.proto},${q(r.app)},${q(r.domain)}\n")
        }
        val name = "packets_${System.currentTimeMillis()}.csv"
        try {
            if (Build.VERSION.SDK_INT >= 29) {
                val v = ContentValues().apply {
                    put(MediaStore.Downloads.DISPLAY_NAME, name)
                    put(MediaStore.Downloads.MIME_TYPE, "text/csv")
                    put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
                }
                val uri = contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, v)!!
                contentResolver.openOutputStream(uri)!!.use { it.write(sb.toString().toByteArray()) }
                Toast.makeText(this, "Saved: Downloads/$name (${snap.size} rows)", Toast.LENGTH_LONG).show()
            } else {
                val f = File(getExternalFilesDir(null), name)
                f.writeText(sb.toString())
                Toast.makeText(this, "Saved: ${f.absolutePath}", Toast.LENGTH_LONG).show()
            }
        } catch (e: Exception) {
            Toast.makeText(this, "Export failed: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        val bg = 0xFF121212.toInt()

        stats = TextView(this).apply {
            textSize = 13f; setTextColor(W); typeface = Typeface.MONOSPACE
            setBackgroundColor(0xFF1E2A38.toInt()); setPadding(dp(14), dp(10), dp(14), dp(10))
        }

        val row1 = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            addView(btn("▶ START") {
                if (!CaptureVpnService.running) {
                    val i = VpnService.prepare(this@MainActivity)
                    if (i != null) startActivityForResult(i, 1) else startVpn()
                }
            })
            addView(btn("■ STOP") { CaptureVpnService.running = false })
            addView(btn("CLEAR") { CaptureVpnService.clearAll(); refresh() })
        }
        val row2 = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            addView(btn("PACKETS") { setMode(0) })
            addView(btn("BY IP") { setMode(1) })
            addView(btn("BY APP") { setMode(2) })
            addView(btn("CSV") { exportCsv() })
        }

        search = EditText(this).apply {
            hint = "search IP / app / domain"
            setHintTextColor(0xFF888888.toInt()); setTextColor(W); textSize = 13f
            setSingleLine(true)
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 2.2f)
            addTextChangedListener(object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
                override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
                override fun afterTextChanged(s: Editable?) { refresh() }
            })
        }
        protoBtn = btn("ALL") {
            protoF = when (protoF) { "ALL" -> "TCP"; "TCP" -> "UDP"; else -> "ALL" }
            protoBtn.text = protoF
            refresh()
        }
        val row3 = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(dp(8), 0, dp(8), 0)
            addView(search); addView(protoBtn)
        }

        header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(dp(6), dp(5), dp(6), dp(5))
            setBackgroundColor(0xFF2C2C2C.toInt())
        }

        adapter = object : BaseAdapter() {
            override fun getCount() = rows.size
            override fun getItem(i: Int) = rows[i]
            override fun getItemId(i: Int) = i.toLong()
            override fun getView(i: Int, v: View?, p: ViewGroup?): View {
                val r = rows[i]; val w = wids[mode]
                val cells = ArrayList<TextView>()
                for (k in r.indices) {
                    if (k >= w.size) break
                    var col = W; var bold = false
                    if (mode == 0) {
                        if (k == 8) {
                            col = when (r[k]) {
                                "TCP" -> 0xFF64B5F6.toInt(); "UDP" -> 0xFF81C784.toInt(); else -> 0xFFBDBDBD.toInt()
                            }
                            bold = true
                        }
                        if (k == 2) { col = if (r[k] == "↑") 0xFFFF8A65.toInt() else 0xFF4DD0E1.toInt(); bold = true }
                        if (k == 4) col = 0xFFFFF59D.toInt()
                    }
                    cells.add(cell(r[k], w[k], col, bold))
                }
                return rowOf(cells).apply {
                    setBackgroundColor(if (i % 2 == 0) 0xFF1A1A1A.toInt() else bg)
                }
            }
        }

        val list = ListView(this).apply {
            this.adapter = this@MainActivity.adapter
            divider = null
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f)
        }
        table = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
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
            addView(stats); addView(row1); addView(row2); addView(row3); addView(hscroll)
        })

        buildHeader()
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
