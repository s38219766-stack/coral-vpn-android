package com.coral.vpn

import android.app.Application
import android.content.Context
import android.content.Intent
import android.util.Log
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Журнал шагов подключения: пишется на диск сразу, поэтому переживает падение приложения. */
object Diag {
    private var file: File? = null

    fun init(ctx: Context) { file = File(ctx.filesDir, "diag.log") }

    fun log(msg: String) {
        Log.w("Coral", msg)
        runCatching {
            file?.appendText("${SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())} $msg\n")
        }
    }

    fun clear() { runCatching { file?.writeText("") } }

    fun report(): String {
        val steps = runCatching { file?.readText() }.getOrNull().orEmpty().takeLast(6000)
        val crash = runCatching {
            val p = Runtime.getRuntime().exec(arrayOf("logcat", "-b", "crash", "-d", "-t", "60"))
            p.inputStream.bufferedReader().readText().takeLast(4000)
        }.getOrDefault("")
        val sys = runCatching {
            val p = Runtime.getRuntime().exec(arrayOf("logcat", "-d", "-t", "120", "Coral:W", "*:S"))
            p.inputStream.bufferedReader().readText().takeLast(9000)
        }.getOrDefault("")
        return "== Шаги ==\n$steps\n== Аварии ==\n$crash\n== Лог ==\n$sys"
    }

    fun share(ctx: Context) {
        val i = Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, report())
        ctx.startActivity(Intent.createChooser(i, "Отправить журнал").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }
}

class CoralApp : Application() {
    override fun onCreate() {
        super.onCreate()
        Diag.init(this)
        val prev = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { t, e ->
            Diag.log("CRASH в потоке ${t.name}: ${Log.getStackTraceString(e)}")
            prev?.uncaughtException(t, e)
        }
    }
}
