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

    // Важные события и сводка повторяющихся ошибок: «середина» журнала при копировании пропускается, а именно там чаще всего
    // и случается обрыв (смена сети, потеря сеанса, переключение способа).
    private val KEY = Regex("сторож|авто:|host (ok|fail)|рукопожатие|поток:|шаг 2|шаг 3|сервер «|проверка связи|CRASH|ct2:|ct:|сеть:|не отвечает|переключ")
    private val NOISE = Regex("туннель за минуту|система: активная сеть|sing-box: .*ERROR")

    private fun events(all: String): String {
        val lines = all.lines()
        val ev = lines.filter { KEY.containsMatchIn(it) && !NOISE.containsMatchIn(it) }.takeLast(70)
        val errs = lines.filter { it.contains("ERROR") }
        val groups = errs.groupBy { l -> l.substringAfter("connection:", l).replace(Regex("\\[[0-9;]*m|\\d{3,}|\\[.*?\\]"), "").trim().take(90) }
        val sum = groups.entries.sortedByDescending { it.value.size }.take(6).joinToString("\n") { (k, v) ->
            "${v.size}× с ${v.first().take(8)} по ${v.last().take(8)}: $k"
        }
        return (if (ev.isEmpty()) "(нет)" else ev.joinToString("\n")) + (if (sum.isEmpty()) "" else "\n-- повторяющиеся ошибки --\n$sum")
    }

    fun report(): String {
        // Начало журнала (какой сервер выбран, как запускались ядра) и конец: середину с повторяющимися проверками отбрасываем
        val all = runCatching { file?.readText() }.getOrNull().orEmpty()
        val steps = if (all.length <= 7500) all else all.take(4000) + "\n… (середина журнала пропущена) …\n" + all.takeLast(3500)
        val crash = runCatching {
            val p = Runtime.getRuntime().exec(arrayOf("logcat", "-b", "crash", "-d", "-t", "60"))
            p.inputStream.bufferedReader().readText().takeLast(4000)
        }.getOrDefault("")
        val sys = runCatching {
            val p = Runtime.getRuntime().exec(arrayOf("logcat", "-d", "-t", "120", "Coral:W", "*:S"))
            p.inputStream.bufferedReader().readText().takeLast(9000)
        }.getOrDefault("")
        return "== Шаги ==\n$steps\n== События ==\n${events(all)}\n== Аварии ==\n$crash\n== Лог ==\n$sys"
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
