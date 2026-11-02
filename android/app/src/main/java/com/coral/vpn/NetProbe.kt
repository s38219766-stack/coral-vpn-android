package com.coral.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.telephony.TelephonyManager
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

/**
 * Анонимная статистика: оператор, тип сети, какой транспорт сработал. Ни адресов, ни имён, ни аккаунта.
 * Помогает сразу ставить первым то, что у вашего оператора работает, и показывает карту блокировок.
 */
object NetProbe {
    fun isWifi(ctx: Context): Boolean = runCatching {
        val cm = ctx.getSystemService(ConnectivityManager::class.java)
        val caps = cm.getNetworkCapabilities(cm.activeNetwork)
        caps != null && !caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
    }.getOrDefault(false)

    fun carrier(ctx: Context): String = runCatching {
        ctx.getSystemService(TelephonyManager::class.java).networkOperatorName.orEmpty()
    }.getOrDefault("")

    private fun netName(ctx: Context) = if (isWifi(ctx)) "wifi" else "mobile"

    /** Порядок транспортов с сервера; при любой ошибке — пустой список (остаётся обычный порядок). */
    fun best(ctx: Context): List<String> = runCatching {
        val q = "carrier=${URLEncoder.encode(carrier(ctx), "UTF-8")}&net=${netName(ctx)}"
        val c = URL("${Api.BASE}/api/net/best?$q").openConnection() as HttpURLConnection
        c.connectTimeout = 3000; c.readTimeout = 3000
        val arr = JSONObject(c.inputStream.bufferedReader().readText()).getJSONArray("order")
        List(arr.length()) { arr.getString(it) }
    }.getOrDefault(emptyList())

    /** Анонимная отметка: ответил ли наш адрес (основной сервер или мост) у этого оператора. */
    fun reportHost(ctx: Context, host: String, ok: Boolean) {
        val body = JSONObject().put("carrier", carrier(ctx)).put("net", netName(ctx)).put("host", host).put("ok", ok).toString()
        Thread {
            runCatching {
                val c = URL("${Api.BASE}/api/net/host").openConnection() as HttpURLConnection
                c.requestMethod = "POST"; c.connectTimeout = 4000; c.readTimeout = 4000; c.doOutput = true
                c.setRequestProperty("Content-Type", "application/json")
                c.outputStream.use { it.write(body.toByteArray()) }
                c.responseCode; c.disconnect()
            }
        }.start()
    }

    fun report(ctx: Context, transport: String, ok: Boolean, ms: Int) {
        val body = JSONObject().put("carrier", carrier(ctx)).put("net", netName(ctx))
            .put("transport", transport).put("ok", ok).put("ms", ms).toString()
        Thread {
            runCatching {
                val c = URL("${Api.BASE}/api/net/report").openConnection() as HttpURLConnection
                c.requestMethod = "POST"; c.connectTimeout = 4000; c.readTimeout = 4000; c.doOutput = true
                c.setRequestProperty("Content-Type", "application/json")
                c.outputStream.use { it.write(body.toByteArray()) }
                c.responseCode; c.disconnect()
            }
        }.start()
    }
}
