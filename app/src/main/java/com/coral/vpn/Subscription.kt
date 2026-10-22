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
)

object Subscription {
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
        )
    }
}
