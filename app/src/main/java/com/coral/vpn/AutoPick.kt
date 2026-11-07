package com.coral.vpn

import org.json.JSONObject
import java.net.InetSocketAddress
import java.net.Socket

/**
 * «Авто»: перед подключением быстро замеряем, до каких серверов сейчас доходит соединение и насколько быстро,
 * и пробуем сначала самые быстрые. Порядок из статистики операторов остаётся при равных замерах.
 */
object AutoPick {
    /** Замеры, различающиеся меньше чем на это число миллисекунд, считаются равными (остаётся порядок из статистики). */
    const val TIE_MS = 80L
    /** Условная оценка для способов, которые нельзя замерить (UDP: Hysteria2, TUIC): ставим их после быстрых TCP-серверов. */
    const val NEUTRAL_MS = 240L

    /** Адрес и порт для замера: для Xray-конфига — сервер из vnext, для нашего протокола — первый хост и середина диапазона портов. */
    fun endpoint(config: String, ctSpec: String): Pair<String, Int>? {
        if (ctSpec.startsWith("ct2|")) {
            val p = ctSpec.split("|")   // ct2|host|port|pub|key
            val host = p.getOrElse(1) { "" }.split(",").firstOrNull { it.isNotBlank() } ?: return null
            return host to (p.getOrElse(2) { "" }.toIntOrNull() ?: return null)
        }
        if (ctSpec.isNotBlank()) {
            val p = ctSpec.split("|")
            val host = p.getOrElse(0) { "" }.split(",").firstOrNull { it.isNotBlank() } ?: return null
            val range = p.getOrElse(1) { "" }.split(":")
            val lo = range.getOrNull(0)?.toIntOrNull() ?: 9500
            val hi = range.getOrNull(1)?.toIntOrNull() ?: lo
            return host to (lo + (hi - lo) / 2)
        }
        return try {
            val s = JSONObject(config).getJSONArray("outbounds").getJSONObject(0).getJSONObject("settings")
            if (!s.has("vnext")) null else {
                val v = s.getJSONArray("vnext").getJSONObject(0)
                v.getString("address") to v.getInt("port")
            }
        } catch (e: Exception) {
            null
        }
    }

    /** Лучшее из двух замеров TCP-соединения, мс; null — не соединилось. */
    fun tcpRtt(host: String, port: Int, timeoutMs: Int = 2000): Long? {
        var best = -1L
        for (attempt in 0 until 2) {
            val t0 = System.nanoTime()
            val ok = try {
                Socket().use { it.connect(InetSocketAddress(host, port), timeoutMs) }
                true
            } catch (e: Exception) {
                false
            }
            if (ok) {
                val ms = (System.nanoTime() - t0) / 1_000_000
                if (best < 0 || ms < best) best = ms
            }
        }
        return if (best < 0) null else best
    }

    /** Добавка к замеру пинга по виду способа (мс): WebSocket и XHTTP идут через сайт-маску и заметно медленнее. */
    const val SLOW_PENALTY_MS = 170L

    fun penaltyFor(key: String?): Long = if (key == "ws" || key == "xhttp") SLOW_PENALTY_MS else 0L

    /** Порядок индексов: сначала быстрые, потом то, что замерить нельзя, потом недоступные; способы «в конец» (дробление) остаются последними. */
    fun order(rtt: List<Long?>, measurable: List<Boolean>, last: List<Boolean>, penalty: List<Long> = emptyList()): List<Int> {
        // penalty — добавка к замеру для способов, которые заведомо медленнее при том же пинге (WebSocket через сайт-маску: на деле соединение
        // 1,5–2 с против 0,4 с у Reality), чтобы они выигрывали только при заметно лучшем пинге или когда остальные недоступны
        fun key(i: Int): Long = when {
            last[i] -> Long.MAX_VALUE
            !measurable[i] -> NEUTRAL_MS / TIE_MS
            rtt[i] == null -> Long.MAX_VALUE - 1
            else -> (rtt[i]!! + penalty.getOrElse(i) { 0L }) / TIE_MS
        }
        return rtt.indices.sortedWith(compareBy<Int>({ key(it) }, { it }))
    }

    /** Замер всех серверов параллельно: общий дедлайн ~3 с на весь замер (раньше каждому потоку давали по 3,5 с подряд, и «мёртвые» способы складывали ожидание до 10 с). */
    fun measure(endpoints: List<Pair<String, Int>?>): List<Long?> {
        val out = arrayOfNulls<Long>(endpoints.size)
        val threads = endpoints.indices.map { i ->
            Thread {
                val e = endpoints[i]
                if (e != null) { val r = tcpRtt(e.first, e.second); synchronized(out) { out[i] = r } }
            }.also { it.isDaemon = true; it.start() }
        }
        val deadline = System.nanoTime() + 3_000_000_000L
        threads.forEach {
            val left = (deadline - System.nanoTime()) / 1_000_000
            if (left > 0) try { it.join(left) } catch (e: InterruptedException) { /* ничего */ }
        }
        return synchronized(out) { out.toList() }
    }
}
