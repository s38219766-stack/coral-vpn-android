package com.coral.vpn

import org.json.JSONArray
import org.json.JSONObject

enum class RouteMode { ALL, RU_DIRECT, BLOCKED }

/** Собирает JSON-конфигурацию Xray для выбранного сервера. */
object XrayConfig {
    const val SOCKS_PORT = 10808

    // Сервисы, которые нужно пускать через VPN в режиме «только заблокированное».
    // Все названия проверены по geosite.dat из Xray-core v24.12.31.
    private val BLOCKED = listOf(
        "geosite:instagram", "geosite:facebook", "geosite:meta", "geosite:twitter", "geosite:youtube",
        "geosite:discord", "geosite:openai", "geosite:linkedin", "geosite:spotify", "geosite:netflix",
        "geosite:notion", "geosite:medium", "geosite:signal", "geosite:telegram", "geosite:whatsapp",
    )

    fun build(s: Server, mode: RouteMode = RouteMode.RU_DIRECT, adblock: Boolean = false): String {
        val root = JSONObject()
        root.put("log", JSONObject().put("loglevel", "warning"))
        root.put("dns", JSONObject().put("servers", JSONArray(listOf("1.1.1.1", "8.8.8.8"))))
        root.put("inbounds", JSONArray().put(
            JSONObject()
                .put("tag", "socks").put("listen", "127.0.0.1").put("port", SOCKS_PORT).put("protocol", "socks")
                .put("settings", JSONObject().put("udp", true))
                .put("sniffing", JSONObject().put("enabled", true).put("destOverride", JSONArray(listOf("http", "tls", "quic"))))
        ))
        root.put("outbounds", JSONArray()
            .put(proxy(s))
            .put(JSONObject().put("tag", "direct").put("protocol", "freedom"))
            .put(JSONObject().put("tag", "block").put("protocol", "blackhole")))
        root.put("routing", routing(mode, adblock))
        return root.toString(2)
    }

    private fun proxy(s: Server): JSONObject {
        val user = JSONObject().put("id", s.uuid).put("encryption", "none")
        if (s.flow.isNotEmpty()) user.put("flow", s.flow)
        val stream = JSONObject().put("network", s.network).put("security", s.security)
        when (s.security) {
            "reality" -> stream.put("realitySettings", JSONObject()
                .put("serverName", s.sni).put("fingerprint", s.fingerprint)
                .put("publicKey", s.publicKey).put("shortId", s.shortId).put("spiderX", ""))
            "tls" -> stream.put("tlsSettings", JSONObject()
                .put("serverName", s.sni.ifEmpty { s.host }).put("fingerprint", s.fingerprint)
                .apply { if (s.alpn.isNotEmpty()) put("alpn", JSONArray(s.alpn)) })
        }
        if (s.network == "ws") {
            val ws = JSONObject().put("path", s.path.ifEmpty { "/" })
            // Host нужен всегда: адрес сервера подменяется на IP, а сайт на домене
            val hostName = s.hostHeader.ifEmpty { s.sni.ifEmpty { s.host } }
            ws.put("headers", JSONObject().put("Host", hostName))
            stream.put("wsSettings", ws)
        }
        return JSONObject().put("tag", "proxy").put("protocol", "vless")
            .put("settings", JSONObject().put("vnext", JSONArray().put(
                JSONObject().put("address", s.host).put("port", s.port).put("users", JSONArray().put(user)))))
            .put("streamSettings", stream)
    }

    private fun routing(mode: RouteMode, adblock: Boolean): JSONObject {
        val rules = JSONArray()
        if (adblock) rules.put(rule("block").put("domain", JSONArray(listOf("geosite:category-ads-all"))))
        // Локальные адреса всегда напрямую
        rules.put(rule("direct").put("ip", JSONArray(listOf("geoip:private"))))
        when (mode) {
            RouteMode.RU_DIRECT -> {
                // Российские сайты — напрямую, остальное — через VPN
                rules.put(rule("direct").put("domain", JSONArray(listOf("regexp:\\.ru$", "regexp:\\.su$", "regexp:\\.xn--p1ai$"))))
                rules.put(rule("direct").put("ip", JSONArray(listOf("geoip:ru"))))
                rules.put(rule("proxy").put("network", "tcp,udp"))
            }
            RouteMode.BLOCKED -> {
                // Через VPN только заблокированные сервисы, всё остальное — напрямую
                rules.put(rule("proxy").put("domain", JSONArray(BLOCKED)))
                rules.put(rule("direct").put("network", "tcp,udp"))
            }
            RouteMode.ALL -> rules.put(rule("proxy").put("network", "tcp,udp"))
        }
        return JSONObject().put("domainStrategy", "IPIfNonMatch").put("rules", rules)
    }

    private fun rule(outbound: String) = JSONObject().put("type", "field").put("outboundTag", outbound)
}
