package com.coral.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * Сканер белых списков: без VPN проверяет, какие сайты открываются (kind=site) и проходит ли до наших адресов
 * TLS-рукопожатие с чужим именем сайта (kind=sni). Никаких данных пользователя: только имена из списка и результат.
 * Результат остаётся на телефоне и уходит анонимно при первой же связи с сервером.
 */
object WlScan {
    val SITES = listOf(
        "www.gosuslugi.ru", "www.mos.ru", "www.nalog.gov.ru", "www.government.ru", "www.cbr.ru", "www.moex.com", "nspk.ru",
        "www.sberbank.ru", "online.sberbank.ru", "www.tbank.ru", "alfabank.ru", "www.vtb.ru", "www.gazprombank.ru",
        "www.rzd.ru", "www.tutu.ru", "www.aeroflot.ru", "www.ozon.ru", "www.wildberries.ru", "www.avito.ru",
        "ya.ru", "yandex.ru", "www.kinopoisk.ru", "vk.com", "ok.ru", "mail.ru", "max.ru", "rutube.ru",
        "2gis.ru", "hh.ru", "www.pochta.ru", "tass.ru", "ria.ru", "www.rbc.ru",
    )
    val CONTROLS = listOf("example.org", "coralsvobod.duckdns.org")
    /** Наши адреса: основной сервер (Caddy), мост (порт ct), «труба» через Россию. */
    val TARGETS = listOf("main" to ("146.103.25.67" to 443), "bridge" to ("31.59.138.21" to 21500), "ru" to ("155.212.139.252" to 443))

    data class Probe(val kind: String, val target: String, val sni: String, val ok: Boolean, val ms: Int)

    private val trustAll: SSLContext = SSLContext.getInstance("TLS").apply {
        init(null, arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(c: Array<X509Certificate>?, a: String?) {}
            override fun checkServerTrusted(c: Array<X509Certificate>?, a: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }), SecureRandom())
    }

    fun vpnActive(ctx: Context): Boolean = runCatching {
        val cm = ctx.getSystemService(ConnectivityManager::class.java)
        cm.getNetworkCapabilities(cm.activeNetwork)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    }.getOrDefault(false)

    /** Рукопожатие TLS с именем sni: true, если сервер ответил (рукопожатие прошло или пришёл alert); false — тишина, сброс, таймаут. */
    private fun hello(host: String?, port: Int, sni: String, timeout: Int): Pair<Boolean, Int> {
        val t0 = System.currentTimeMillis()
        val raw = Socket()
        val ok = try {
            val addr = if (host == null) InetAddress.getByName(sni) else InetAddress.getByName(host)
            raw.connect(InetSocketAddress(addr, port), timeout)
            raw.soTimeout = timeout
            val ssl = trustAll.socketFactory.createSocket(raw, sni, port, true) as SSLSocket
            ssl.sslParameters = ssl.sslParameters.also { it.serverNames = listOf(SNIHostName(sni)) }
            ssl.startHandshake()
            true
        } catch (e: SSLHandshakeException) {
            val m = e.message.orEmpty().lowercase()
            "alert" in m || "certificate" in m
        } catch (e: Exception) {
            false
        } finally {
            runCatching { raw.close() }
        }
        return ok to (System.currentTimeMillis() - t0).toInt()
    }

    fun run(): List<Probe> {
        val jobs = mutableListOf<Callable<Probe>>()
        for (d in SITES) jobs += Callable { hello(null, 443, d, 4000).let { Probe("site", "", d, it.first, it.second) } }
        for ((label, hp) in TARGETS) for (d in CONTROLS + SITES)
            jobs += Callable { hello(hp.first, hp.second, d, 3500).let { Probe("sni", label, d, it.first, it.second) } }
        val pool = Executors.newFixedThreadPool(16)
        return try { pool.invokeAll(jobs).map { it.get() } } finally { pool.shutdownNow() }
    }

    fun summary(r: List<Probe>): String {
        val sb = StringBuilder()
        val sites = r.filter { it.kind == "site" }
        val open = sites.filter { it.ok }.map { it.sni.removePrefix("www.") }
        sb.append("Сайты открываются: ${open.size} из ${sites.size}\n").append(if (open.isEmpty()) "—" else open.joinToString(", ")).append("\n\n")
        for ((label, _) in TARGETS) {
            val t = r.filter { it.kind == "sni" && it.target == label }
            val ctl = t.filter { it.sni in CONTROLS }
            val ctlOk = ctl.filter { it.ok }.map { it.sni }
            val pass = t.filter { it.sni in SITES && it.ok }.map { it.sni.removePrefix("www.") }
            sb.append("Наш адрес «$label»: нейтральные имена ${if (ctlOk.isEmpty()) "НЕ проходят" else "проходят"}, имена из списка прошли ${pass.size} из ${SITES.size}\n")
            if (pass.isNotEmpty() && ctlOk.isEmpty()) sb.append("→ маскировка по имени РАБОТАЕТ: ${pass.take(12).joinToString(", ")}\n")
            sb.append("\n")
        }
        return sb.toString().trim()
    }

    private fun prefs(ctx: Context) = ctx.getSharedPreferences("coral", Context.MODE_PRIVATE)

    /** Запускает проверку, пишет в журнал, ставит отправку в очередь и пробует отправить. Возвращает текст для экрана. */
    fun runAndStore(ctx: Context): String {
        val r = run()
        val s = summary(r)
        Diag.log("wlscan ${NetProbe.carrier(ctx)} ${if (NetProbe.isWifi(ctx)) "wifi" else "mobile"}\n$s")
        val arr = JSONArray(prefs(ctx).getString("wl_pending", "[]"))
        val batch = JSONObject().put("carrier", NetProbe.carrier(ctx)).put("net", if (NetProbe.isWifi(ctx)) "wifi" else "mobile")
            .put("items", JSONArray(r.map { JSONObject().put("k", it.kind).put("t", it.target).put("s", it.sni).put("ok", it.ok) }))
        arr.put(batch)
        while (arr.length() > 5) arr.remove(0)
        prefs(ctx).edit().putString("wl_pending", arr.toString()).apply()
        flush(ctx)
        return s
    }

    /** Отправляет накопленное; при отсутствии связи с сервером оставляет в очереди. */
    fun flush(ctx: Context) {
        Thread {
            runCatching {
                val arr = JSONArray(prefs(ctx).getString("wl_pending", "[]"))
                var i = 0
                while (i < arr.length()) {
                    val c = URL("${Api.BASE}/api/net/wl").openConnection() as HttpURLConnection
                    c.requestMethod = "POST"; c.connectTimeout = 4000; c.readTimeout = 6000; c.doOutput = true
                    c.setRequestProperty("Content-Type", "application/json")
                    c.outputStream.use { it.write(arr.getJSONObject(i).toString().toByteArray()) }
                    val code = c.responseCode; c.disconnect()
                    if (code in 200..299 || code == 400) arr.remove(i) else break
                }
                prefs(ctx).edit().putString("wl_pending", arr.toString()).apply()
            }
        }.start()
    }
}
