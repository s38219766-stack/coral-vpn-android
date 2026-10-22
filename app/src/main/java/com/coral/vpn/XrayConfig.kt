package com.coral.vpn

import org.json.JSONArray
import org.json.JSONObject

enum class RouteMode { ALL, RU_DIRECT }

/** Собирает JSON-конфигурацию Xray для выбранного сервера. */
object XrayConfig {
    const val SOCKS_PORT = 10808

    fun build(s: Server, mode: RouteMode = RouteMode.RU_DIRECT): String {
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
        root.put("routing", routing(mode))
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
            if (s.hostHeader.isNotEmpty()) ws.put("headers", JSONObject().put("Host", s.hostHeader))
            stream.put("wsSettings", ws)
        }
        return JSONObject().put("tag", "proxy").put("protocol", "vless")
            .put("settings", JSONObject().put("vnext", JSONArray().put(
                JSONObject().put("address", s.host).put("port", s.port).put("users", JSONArray().put(user)))))
            .put("streamSettings", stream)
    }

    private fun routing(mode: RouteMode): JSONObject {
        val rules = JSONArray()
        // Локальные адреса всегда напрямую
        rules.put(rule("direct").put("ip", JSONArray(listOf("geoip:private"))))
        if (mode == RouteMode.RU_DIRECT) {
            // Российские сайты — напрямую, остальное — через VPN
            rules.put(rule("direct").put("domain", JSONArray(listOf("regexp:\\.ru$", "regexp:\\.su$", "regexp:\\.xn--p1ai$"))))
            rules.put(rule("direct").put("ip", JSONArray(listOf("geoip:ru"))))
        }
        rules.put(rule("proxy").put("network", "tcp,udp"))
        return JSONObject().put("domainStrategy", "IPIfNonMatch").put("rules", rules)
    }

    private fun rule(outbound: String) = JSONObject().put("type", "field").put("outboundTag", outbound)
}
