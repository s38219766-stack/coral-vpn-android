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

    /** Порядок индексов: сначала быстрые, потом то, что замерить нельзя, потом недоступные; способы «в конец» (дробление) остаются последними. */
    fun order(rtt: List<Long?>, measurable: List<Boolean>, last: List<Boolean>): List<Int> {
        fun key(i: Int): Long = when {
            last[i] -> Long.MAX_VALUE
            !measurable[i] -> NEUTRAL_MS / TIE_MS
            rtt[i] == null -> Long.MAX_VALUE - 1
            else -> rtt[i]!! / TIE_MS
        }
        return rtt.indices.sortedWith(compareBy<Int>({ key(it) }, { it }))
    }

    /** Замер всех серверов параллельно, не дольше ~3,5 с. */
    fun measure(endpoints: List<Pair<String, Int>?>): List<Long?> {
        val out = arrayOfNulls<Long>(endpoints.size)
        val threads = endpoints.indices.map { i ->
            Thread {
                val e = endpoints[i]
                if (e != null) out[i] = tcpRtt(e.first, e.second)
            }.also { it.start() }
        }
        threads.forEach { try { it.join(3500) } catch (e: InterruptedException) { /* ничего */ } }
        return out.toList()
    }
}
