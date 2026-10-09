package com.example.packetmonitor

import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Path
import android.graphics.Typeface
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.provider.MediaStore
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.view.View
import android.view.ViewGroup
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

class Graph(ctx: Context) : View(ctx) {
    private val inS = ArrayList<Long>()
    private val outS = ArrayList<Long>()
    private val pIn = Paint().apply { color = 0xFF4DD0E1.toInt(); strokeWidth = 4f; style = Paint.Style.STROKE; isAntiAlias = true }
    private val pOut = Paint().apply { color = 0xFFFF8A65.toInt(); strokeWidth = 4f; style = Paint.Style.STROKE; isAntiAlias = true }
    private val pTxt = Paint().apply { color = 0xFFAAAAAA.toInt(); textSize = 26f; isAntiAlias = true }

    fun add(i: Long, o: Long) {
        inS.add(i); outS.add(o)
        if (inS.size > 60) { inS.removeAt(0); outS.removeAt(0) }
        invalidate()
    }

    override fun onDraw(c: Canvas) {
        c.drawColor(0xFF161B22.toInt())
        var mx = 1024L
        for (v in inS) if (v > mx) mx = v
        for (v in outS) if (v > mx) mx = v
        val w = width.toFloat(); val h = height.toFloat()
        fun line(d: ArrayList<Long>, p: Paint) {
            if (d.size < 2) return
            val path = Path()
            for (k in d.indices) {
                val x = w * k / 59f
                val y = h - 8f - (h - 16f) * d[k].toFloat() / mx.toFloat()
                if (k == 0) path.moveTo(x, y) else path.lineTo(x, y)
            }
            c.drawPath(path, p)
        }
        line(inS, pIn); line(outS, pOut)
        c.drawText("max ${mx / 1024} KB/s   cyan=down  orange=up", 8f, 28f, pTxt)
    }
}

class MainActivity : AppCompatActivity() {
    private val h = Handler(Looper.getMainLooper())
    private lateinit var stats: TextView
    private lateinit var adapter: BaseAdapter
    private lateinit var header: LinearLayout
    private lateinit var table: LinearLayout
    private lateinit var hscroll: HorizontalScrollView
    private lateinit var search: EditText
    private lateinit var protoBtn: Button
    private lateinit var timeBtn: Button
    private lateinit var rangeBtn: Button
    private lateinit var autoBtn: Button
    private lateinit var adBtn: Button
    private lateinit var graph: Graph
    private val rows = ArrayList<List<String>>()
    private var mode = 0
    private var protoF = "ALL"
    private var timeIdx = 0
    private var rangeIdx = 0
    private val timeNames = arrayOf("ALL", "1m", "10m", "1h")
    private val timeMs = longArrayOf(0L, 60000L, 600000L, 3600000L)
    private val rangeNames = arrayOf("Today", "7 days", "Month", "All")
    private var lastBi = 0L; private var lastBo = 0L; private var lastPi = 0L; private var lastPo = 0L
    private val W = 0xFFEEEEEE.toInt()
    private val HC = 0xFFFFD54F.toInt()

    private val heads = arrayOf(
        arrayOf("Date", "Time.ms", "", "Size", "App", "Source IP:Port", "Dest IP:Port", "Domain", "Proto"),
        arrayOf("Server IP", "Domain", "Sent", "Received", "Packets"),
        arrayOf("App", "Sent", "Received", "Packets", "Status"),
        arrayOf("App", "Sent", "Received", "Total", "Daily limit")
    )
    private val wids = arrayOf(
        intArrayOf(85, 95, 28, 60, 110, 150, 150, 170, 50),
        intArrayOf(140, 190, 90, 90, 70),
        intArrayOf(170, 100, 100, 80, 110),
        intArrayOf(170, 90, 90, 90, 120)
    )

    private fun dp(x: Int) = (x * resources.displayMetrics.density).toInt()

    private fun onOff(b: Boolean) = if (b) "ON" else "OFF"

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
        text = t; textSize = 11f
        minHeight = 0; minimumHeight = 0
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
        val now = System.currentTimeMillis()
        val lim = timeMs[timeIdx]
        when (mode) {
            0 -> synchronized(CaptureVpnService.log) {
                for (r in CaptureVpnService.log) {
                    if (lim > 0L && now - r.ts > lim) continue
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
            2 -> {
                val items = CaptureVpnService.appStats.entries.sortedByDescending { it.value[0] + it.value[1] }
                for (e in items) {
                    val v = e.value
                    val st = if (CaptureVpnService.blocked.contains(e.key)) "BLOCKED" else ""
                    val c = listOf(e.key, fmt(v[0]), fmt(v[1]), "${v[2]}", st)
                    if (q.isEmpty() || c.joinToString(" ").lowercase().contains(q)) rows.add(c)
                }
            }
            else -> {
                val rep = Store.report(rangeIdx)
                var ts = 0L; var tr = 0L
                for (t in rep) { ts += t.second; tr += t.third }
                rows.add(listOf("TOTAL", fmt(ts), fmt(tr), fmt(ts + tr), ""))
                for (t in rep) {
                    if (q.isNotEmpty() && !t.first.lowercase().contains(q)) continue
                    val l = Store.limits[t.first]
                    val ls = if (l != null) "${l / 1048576L} MB/day" else ""
                    rows.add(listOf(t.first, fmt(t.second), fmt(t.third), fmt(t.second + t.third), ls))
                }
            }
        }
    }

    private fun refresh() { rebuild(); adapter.notifyDataSetChanged() }

    private fun setMode(m: Int) { mode = m; buildHeader(); refresh(); hscroll.scrollTo(0, 0) }

    private val ticker = object : Runnable {
        override fun run() {
            val bi = CaptureVpnService.bytesIn.get(); val bo = CaptureVpnService.bytesOut.get()
            val pi = CaptureVpnService.pktIn.get(); val po = CaptureVpnService.pktOut.get()
            val di = maxOf(0L, bi - lastBi); val dO = maxOf(0L, bo - lastBo)
            graph.add(di, dO)
            stats.text = "⬇ Received: ${fmt(bi)}  (${fmt(di)}/s)\n" +
                "⬆ Sent: ${fmt(bo)}  (${fmt(dO)}/s)\n" +
                "Packets in: $pi  (+${maxOf(0L, pi - lastPi)}/s)  out: $po  (+${maxOf(0L, po - lastPo)}/s)\n" +
                "Capture: ${onOff(CaptureVpnService.running)} | Servers: ${CaptureVpnService.ipStats.size} | Apps: ${CaptureVpnService.appStats.size}\n" +
                "Blocked apps: ${CaptureVpnService.blocked.size} | Dropped: ${CaptureVpnService.blockedCount.get()} | Limits: ${Store.limits.size}\n" +
                "AutoBlock: ${onOff(Store.autoBlock)} | AdBlock: ${onOff(Store.adBlock)} | DNS blocked: ${CaptureVpnService.domainBlocked.get()}"
            lastBi = bi; lastBo = bo; lastPi = pi; lastPo = po
            refresh()
            h.postDelayed(this, 1000)
        }
    }

    private fun q(s: String) = "\"" + s.replace("\"", "\"\"") + "\""

    private fun saveFile(name: String, bytes: ByteArray) {
        try {
            if (Build.VERSION.SDK_INT >= 29) {
                val v = ContentValues().apply {
                    put(MediaStore.Downloads.DISPLAY_NAME, name)
                    put(MediaStore.Downloads.MIME_TYPE, "application/octet-stream")
                    put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
                }
                val uri = contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, v)!!
                contentResolver.openOutputStream(uri)!!.use { it.write(bytes) }
                Toast.makeText(this, "Saved: Downloads/$name", Toast.LENGTH_LONG).show()
            } else {
                val f = File(getExternalFilesDir(null), name)
                f.writeBytes(bytes)
                Toast.makeText(this, "Saved: ${f.absolutePath}", Toast.LENGTH_LONG).show()
            }
        } catch (e: Exception) {
            Toast.makeText(this, "Export failed: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    private fun exportCsv() {
        val snap = synchronized(CaptureVpnService.log) { ArrayList(CaptureVpnService.log) }
        val sb = StringBuilder("Date,Time,Direction,Size,Source,Destination,Proto,App,Domain\n")
        for (r in snap.reversed()) {
            sb.append("${r.date},${r.time},${if (r.out) "OUT" else "IN"},${r.size},${r.src},${r.dst},${r.proto},${q(r.app)},${q(r.domain)}\n")
        }
        saveFile("packets_${System.currentTimeMillis()}.csv", sb.toString().toByteArray())
    }

    private fun exportPcap() {
        val snap = synchronized(CaptureVpnService.pcap) { ArrayList(CaptureVpnService.pcap) }
        var size = 24
        for (p in snap) size += 16 + p.second.size
        val bb = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN)
        bb.putInt(0xA1B2C3D4.toInt())
        bb.putShort(2); bb.putShort(4)
        bb.putInt(0); bb.putInt(0); bb.putInt(65535); bb.putInt(101)
        for (p in snap) {
            bb.putInt((p.first / 1000L).toInt())
            bb.putInt(((p.first % 1000L) * 1000L).toInt())
            bb.putInt(p.second.size); bb.putInt(p.second.size)
            bb.put(p.second)
        }
        saveFile("capture_${System.currentTimeMillis()}.pcap", bb.array())
    }

    private fun saveBlocked() {
        getSharedPreferences("pm", MODE_PRIVATE).edit()
            .putStringSet("blocked", HashSet(CaptureVpnService.blocked)).apply()
    }

    private fun askLimit(app: String) {
        val et = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_NUMBER
            hint = "MB per day (0 = remove limit)"
            val cur = Store.limits[app]
            if (cur != null) setText("${cur / 1048576L}")
        }
        android.app.AlertDialog.Builder(this)
            .setTitle("Daily limit: $app")
            .setView(et)
            .setPositiveButton("Save") { _, _ ->
                val mbv = et.text.toString().toLongOrNull() ?: 0L
                if (mbv <= 0L) Store.limits.remove(app) else Store.limits[app] = mbv * 1048576L
                Store.saveLimits()
                Store.alerted.removeAll { it.endsWith("\t$app") }
                refresh()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun pickApp() {
        val names = ArrayList<String>()
        names.addAll(CaptureVpnService.appStats.keys)
        for (k in Store.limits.keys) if (!names.contains(k)) names.add(k)
        for (k in Store.usage.keys) {
            val a = k.substringAfter('\t')
            if (!names.contains(a)) names.add(a)
        }
        names.removeAll { it == "-" || it == "?" }
        names.sort()
        if (names.isEmpty()) {
            Toast.makeText(this, "No apps yet. Start capture first.", Toast.LENGTH_SHORT).show()
            return
        }
        android.app.AlertDialog.Builder(this)
            .setTitle("Pick app")
            .setItems(names.toTypedArray()) { _, i -> askLimit(names[i]) }
            .show()
    }

    private fun askDomain() {
        val et = EditText(this).apply {
            hint = "domain e.g. ads.example.com"
            setSingleLine(true)
        }
        android.app.AlertDialog.Builder(this)
            .setTitle("Block domain")
            .setView(et)
            .setPositiveButton("Add") { _, _ ->
                val d = et.text.toString().trim().lowercase()
                if (d.contains(".") && !d.contains(" ")) {
                    Store.customDomains.add(d); Store.saveFlags()
                    Toast.makeText(this, "Blocked: $d", Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(this, "Invalid domain", Toast.LENGTH_SHORT).show()
                }
            }
            .setNeutralButton("List") { _, _ -> listDomains() }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun listDomains() {
        val l = Store.customDomains.sorted()
        if (l.isEmpty()) {
            Toast.makeText(this, "No custom blocked domains", Toast.LENGTH_SHORT).show()
            return
        }
        android.app.AlertDialog.Builder(this)
            .setTitle("Tap a domain to unblock")
            .setItems(l.toTypedArray()) { _, i ->
                Store.customDomains.remove(l[i]); Store.saveFlags()
                Toast.makeText(this, "Unblocked: ${l[i]}", Toast.LENGTH_SHORT).show()
            }
            .show()
    }

    private fun confirmBlockDomain(dm: String) {
        android.app.AlertDialog.Builder(this)
            .setTitle("Block this domain?")
            .setMessage(dm)
            .setPositiveButton("Block") { _, _ ->
                Store.customDomains.add(dm.lowercase()); Store.saveFlags()
                Toast.makeText(this, "Blocked: $dm", Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        Store.init(this)
        val bg = 0xFF121212.toInt()

        val saved = getSharedPreferences("pm", MODE_PRIVATE).getStringSet("blocked", null)
        if (saved != null) CaptureVpnService.blocked.addAll(saved)
        if (Build.VERSION.SDK_INT >= 33) {
            requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 2)
        }

        stats = TextView(this).apply {
            textSize = 12f; setTextColor(W); typeface = Typeface.MONOSPACE
            setBackgroundColor(0xFF1E2A38.toInt()); setPadding(dp(14), dp(6), dp(14), dp(6))
        }
        graph = Graph(this).apply {
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(50))
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
            addView(btn("PCAP") { exportPcap() })
        }
        rangeBtn = btn("Today") {
            rangeIdx = (rangeIdx + 1) % rangeNames.size
            rangeBtn.text = rangeNames[rangeIdx]
            if (mode == 3) refresh()
        }
        val row4 = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            addView(btn("REPORT") { setMode(3) })
            addView(rangeBtn)
            addView(btn("LIMIT") { pickApp() })
            addView(btn("CLR HIST") {
                android.app.AlertDialog.Builder(this@MainActivity)
                    .setTitle("Delete saved usage history?")
                    .setPositiveButton("Delete") { _, _ -> Store.usage.clear(); Store.flush(); refresh() }
                    .setNegativeButton("Cancel", null)
                    .show()
            })
        }
        autoBtn = btn("AUTOBLK: ${onOff(Store.autoBlock)}") {
            Store.autoBlock = !Store.autoBlock
            Store.saveFlags()
            autoBtn.text = "AUTOBLK: ${onOff(Store.autoBlock)}"
        }
        adBtn = btn("ADBLOCK: ${onOff(Store.adBlock)}") {
            Store.adBlock = !Store.adBlock
            Store.saveFlags()
            adBtn.text = "ADBLOCK: ${onOff(Store.adBlock)}"
        }
        val row5 = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            addView(autoBtn)
            addView(adBtn)
            addView(btn("DOMAINS") { askDomain() })
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
        timeBtn = btn("ALL") {
            timeIdx = (timeIdx + 1) % timeNames.size
            timeBtn.text = timeNames[timeIdx]
            refresh()
        }
        val row3 = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(dp(8), 0, dp(8), 0)
            addView(search); addView(protoBtn); addView(timeBtn)
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
                        if (k == 7 && r[k].startsWith("✖")) { col = 0xFFFF5252.toInt(); bold = true }
                    }
                    if (mode == 2 && k == 4) { col = 0xFFFF5252.toInt(); bold = true }
                    if (mode == 3 && r[0] == "TOTAL") { col = HC; bold = true }
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
            setOnItemClickListener { _, _, pos, _ ->
                if (pos < rows.size) {
                    if (mode == 0) {
                        val dm = rows[pos][7].removePrefix("✖ ").trim()
                        if (dm.isNotEmpty()) confirmBlockDomain(dm)
                    } else if (mode == 1 || mode == 2) {
                        search.setText(rows[pos][0])
                        setMode(0)
                    } else if (mode == 3 && rows[pos][0] != "TOTAL") {
                        askLimit(rows[pos][0])
                    }
                }
            }
            setOnItemLongClickListener { _, _, pos, _ ->
                if (mode == 2 && pos < rows.size) {
                    val name = rows[pos][0]
                    if (CaptureVpnService.blocked.contains(name)) {
                        CaptureVpnService.blocked.remove(name)
                        Toast.makeText(this@MainActivity, "Unblocked: $name", Toast.LENGTH_SHORT).show()
                    } else {
                        CaptureVpnService.blocked.add(name)
                        Toast.makeText(this@MainActivity, "Blocked: $name", Toast.LENGTH_SHORT).show()
                    }
                    saveBlocked()
                    refresh()
                }
                true
            }
        }
        table = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(header); addView(list)
        }
        hscroll = HorizontalScrollView(this).apply {
            isFillViewport = true
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f)
            addView(table)
        }

        setContentView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(bg)
            addView(stats); addView(graph); addView(row1); addView(row2); addView(row4); addView(row5); addView(row3); addView(hscroll)
        })

        buildHeader()
        h.post(ticker)

        if (!CaptureVpnService.running && VpnService.prepare(this) == null) startVpn()
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
