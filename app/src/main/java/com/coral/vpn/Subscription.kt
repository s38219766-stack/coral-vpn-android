package com.coral.vpn

import java.net.URI
import java.net.URLDecoder
import java.util.Base64

/** Один сервер из подписки Marzban (VLESS). */
data class Server(
    val name: String,
    val uuid: String,
    val host: String,
    val port: Int,
    val network: String,        // tcp | ws
    val security: String,       // reality | tls | none
    val sni: String,
    val fingerprint: String,
    val publicKey: String,
    val shortId: String,
    val flow: String,
    val path: String,
    val hostHeader: String,
    val alpn: List<String>,
    val mode: String = "",      // XHTTP: auto | packet-up | stream-up
    val extra: String = "",     // XHTTP: дополнительные параметры (JSON)
    val kind: String = "vless", // vless | hysteria2 | tuic | ss2022 | ct | shadowtls (остальные идут через ядро sing-box)
    val secret: String = "",    // пароль Hysteria2 / Shadow-TLS
    val ssMethod: String = "",  // Shadow-TLS: метод Shadowsocks внутри
    val ssPassword: String = "",
    val ctKey: String = "",     // Coral Transport: ключ пользователя (hex)
    val ports: String = "",     // Hysteria2: диапазон портов для прыжков, например 20000:30000
)

object Subscription {
    /** Ответ /api/app/extra: дополнительные серверы Hysteria2, TUIC и Shadow-TLS. */
    fun parseExtra(json: String): List<Server> {
        val arr = org.json.JSONObject(json).optJSONArray("servers") ?: return emptyList()
        return (0 until arr.length()).mapNotNull { i ->
            runCatching {
                val o = arr.getJSONObject(i)
                val kind = o.getString("kind")
                if (kind != "hysteria2" && kind != "shadowtls" && kind != "tuic" && kind != "ss2022" && kind != "ct") return@runCatching null
                Server(
                    name = o.getString("name"), uuid = o.optString("uuid"), host = o.getString("host"), port = o.optInt("port", 0),
                    network = "tcp", security = "none", sni = o.optString("sni"), fingerprint = "chrome", publicKey = "", shortId = "",
                    flow = "", path = "", hostHeader = "", alpn = emptyList(),
                    kind = kind, secret = o.getString("password"),
                    ssMethod = o.optString("ss_method"), ssPassword = o.optString("ss_password"), ports = o.optString("ports"), ctKey = o.optString("ct_key"),
                )
            }.getOrNull()
        }
    }

    /** Подписка — это base64 со списком ссылок по строкам (или сами ссылки). */
    fun parse(body: String): List<Server> {
        val text = body.trim()
        val decoded = if (text.contains("://")) text else runCatching {
            String(Base64.getMimeDecoder().decode(text), Charsets.UTF_8)
        }.getOrDefault(text)
        return decoded.lines().map { it.trim() }
            .filter { it.startsWith("vless://") }
            .mapNotNull { runCatching { parseVless(it) }.getOrNull() }
    }

    fun parseVless(link: String): Server {
        val uri = URI(link)
        val q = (uri.rawQuery ?: "").split("&").filter { it.contains("=") }.associate {
            val (k, v) = it.split("=", limit = 2)
            k to URLDecoder.decode(v, "UTF-8")
        }
        val name = uri.rawFragment?.let { URLDecoder.decode(it, "UTF-8") } ?: uri.host
        return Server(
            name = name,
            uuid = requireNotNull(uri.userInfo) { "no uuid" },
            host = requireNotNull(uri.host) { "no host" },
            port = if (uri.port > 0) uri.port else 443,
            network = q["type"].orEmpty().ifEmpty { "tcp" },
            security = q["security"].orEmpty().ifEmpty { "none" },
            sni = q["sni"].orEmpty(),
            fingerprint = q["fp"].orEmpty().ifEmpty { "chrome" },
            publicKey = q["pbk"].orEmpty(),
            shortId = q["sid"].orEmpty(),
            flow = q["flow"].orEmpty(),
            path = q["path"].orEmpty(),
            hostHeader = q["host"].orEmpty(),
            alpn = q["alpn"].orEmpty().split(",").filter { it.isNotBlank() },
            mode = q["mode"].orEmpty(),
            extra = q["extra"].orEmpty(),
        )
    }
}
