package com.coral.vpn

import org.json.JSONArray
import org.json.JSONObject

enum class RouteMode { ALL, RU_DIRECT, BLOCKED }

/** Собирает JSON-конфигурацию Xray для выбранного сервера. */
object XrayConfig {
    const val SOCKS_PORT = 10808

    /** Страны, сервисы которых можно пускать напрямую: код (как в geoip.dat) и название */
    val COUNTRIES = listOf("kz" to "Казахстан", "ge" to "Грузия", "by" to "Беларусь", "am" to "Армения", "uz" to "Узбекистан", "kg" to "Киргизия", "tj" to "Таджикистан", "az" to "Азербайджан", "md" to "Молдова")

    // Сервисы, которые нужно пускать через VPN в режиме «только заблокированное».
    // Все названия проверены по geosite.dat из Xray-core v24.12.31.
    private val BLOCKED = listOf(
        "geosite:instagram", "geosite:facebook", "geosite:meta", "geosite:twitter", "geosite:youtube",
        "geosite:discord", "geosite:openai", "geosite:linkedin", "geosite:spotify", "geosite:netflix",
        "geosite:notion", "geosite:medium", "geosite:signal", "geosite:telegram", "geosite:whatsapp",
    )

    // Всегда через VPN, что бы ни показали адреса и DNS: сервисы Google и нейросетей. Правило стоит выше любых «напрямую», поэтому подменённый
    // DNS оператора или российский узел Google не отправят их мимо VPN (сайт тогда видит российский адрес и пишет «страна не поддерживается»).
    private val ALWAYS_VPN = listOf(
        "geosite:google", "geosite:google-gemini", "geosite:openai", "geosite:perplexity", "geosite:category-ai-chat-!cn", "geosite:youtube",
        "domain:gemini.google.com", "domain:ai.google.dev", "domain:aistudio.google.com", "domain:notebooklm.google.com", "domain:generativelanguage.googleapis.com",
        "domain:anthropic.com", "domain:claude.ai", "domain:chatgpt.com", "domain:openai.com", "domain:oaistatic.com", "domain:oaiusercontent.com",
        "domain:copilot.microsoft.com", "domain:x.ai", "domain:grok.com", "domain:mistral.ai", "domain:poe.com", "domain:huggingface.co",
    )

    // Российские сайты и сервисы напрямую. Имена geosite проверены по geosite.dat из Xray-core v24.12.31.
    private val RU_DOMAINS = listOf(
        "domain:ru", "domain:su", "domain:xn--p1ai", "geosite:category-ru", "geosite:yandex", "geosite:vk",
        "geosite:mailru", "geosite:ok", "geosite:category-gov-ru",
        // сервисы на не-российских доменах: банки, маркетплейсы, CDN
        "domain:sberbank.com", "domain:tinkoff.com", "domain:vtb.com", "domain:alfabank.com", "domain:2gis.com",
        "domain:ozon.ru", "domain:ozone.ru", "domain:ozonusercontent.com", "domain:wbstatic.net", "domain:avito.st",
        "domain:userapi.com", "domain:vk-cdn.net", "domain:vkuser.net", "domain:mycdn.me", "domain:yandex.net",
        "domain:yandex.com", "domain:yastatic.net", "domain:rustore.ru", "domain:mts.ru",
    )

    fun build(s: Server, mode: RouteMode = RouteMode.RU_DIRECT, adblock: Boolean = false, mobile: Boolean = false, fragment: Boolean = false,
              viaVpn: List<String> = emptyList(), direct: List<String> = emptyList(),
              countries: List<String> = emptyList(), compat: Boolean = false): String {
        val root = JSONObject()
        root.put("log", JSONObject().put("loglevel", "warning"))
        // Режим совместимости: прежние правила (обычный DNS, выбор пути по адресу, без блокировки IPv6) — на случай, если новые мешают
        root.put("dns", if (compat) JSONObject().put("servers", JSONArray(listOf("1.1.1.1", "8.8.8.8"))) else dnsConfig(mode))
        root.put("inbounds", JSONArray().put(
            JSONObject()
                .put("tag", "socks").put("listen", "127.0.0.1").put("port", SOCKS_PORT).put("protocol", "socks")
                .put("settings", JSONObject().put("udp", true))
                .put("sniffing", JSONObject().put("enabled", true).put("destOverride", JSONArray(listOf("http", "tls", "quic"))).put("routeOnly", true))
        ))
        root.put("outbounds", JSONArray()
            .put(if (s.kind == "vless") proxy(s, mobile, fragment) else socksOutbound())
            .put(JSONObject().put("tag", "direct").put("protocol", "freedom"))
            .put(JSONObject().put("tag", "block").put("protocol", "blackhole"))
            .apply { if (fragment && s.kind == "vless") put(fragmentOutbound()) })
        root.put("routing", routing(mode, adblock, mobile, viaVpn, direct, countries, compat))
        return root.toString(2)
    }

    /**
     * DNS самого Xray. Обычный DNS через оператора в России могут подменять (особенно для «неудобных» сайтов), а по подменённому
     * адресу прежние правила отправляли сайт напрямую, и он видел российский адрес. Поэтому основной DNS — DoH через прокси,
     * а российские домены, которые и так идут напрямую, разрешает Яндекс DNS (запрос уходит напрямую, как и сам сайт).
     */
    private fun dnsConfig(mode: RouteMode): JSONObject {
        val servers = JSONArray()
        if (mode == RouteMode.RU_DIRECT) {
            servers.put(JSONObject().put("address", "77.88.8.8").put("domains", JSONArray(RU_DOMAINS)).put("skipFallback", true))
        }
        servers.put(JSONObject().put("address", "https://1.1.1.1/dns-query"))
        servers.put(JSONObject().put("address", "https://8.8.8.8/dns-query"))
        return JSONObject().put("tag", "dns-in").put("servers", servers).put("queryStrategy", "UseIPv4")
    }

    /** Выход, который режет первый пакет TLS на мелкие куски: фильтры не успевают собрать его и разобрать. */
    private fun fragmentOutbound() = JSONObject().put("tag", "fragment").put("protocol", "freedom")
        .put("settings", JSONObject().put("fragment", JSONObject()
            .put("packets", "tlshello").put("length", "100-200").put("interval", "10-20")))

    /** Для Hysteria2 и Shadow-TLS трафик отдаём локальному ядру sing-box; маршрутизация, приложения и сайты остаются в Xray. */
    private fun socksOutbound() = JSONObject().put("tag", "proxy").put("protocol", "socks")
        .put("settings", JSONObject().put("servers", JSONArray().put(
            JSONObject().put("address", "127.0.0.1").put("port", SingBoxConfig.SOCKS_PORT))))

    private fun proxy(s: Server, mobile: Boolean = false, fragment: Boolean = false): JSONObject {
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
        if (s.network == "xhttp") {
            val xh = JSONObject()
                .put("path", s.path.ifEmpty { "/" })
                .put("host", s.hostHeader.ifEmpty { s.sni.ifEmpty { s.host } })
                .put("mode", s.mode.ifEmpty { "auto" })
            if (s.extra.isNotEmpty()) runCatching { xh.put("extra", JSONObject(s.extra)) }
            stream.put("xhttpSettings", xh)
        }
        // Мобильный режим: без задержки отправки мелких пакетов и (для WS) объединение соединений в одно
        if (mobile || fragment) {
            val sock = JSONObject()
            if (mobile) sock.put("tcpNoDelay", true)
                .put("tcpKeepAliveInterval", 30)   // держим соединение «живым» для NAT оператора
                .put("tcpKeepAliveIdle", 30)
            if (fragment) sock.put("dialerProxy", "fragment")
            stream.put("sockopt", sock)
        }
        val out = JSONObject().put("tag", "proxy").put("protocol", "vless")
            .put("settings", JSONObject().put("vnext", JSONArray().put(
                JSONObject().put("address", s.host).put("port", s.port).put("users", JSONArray().put(user)))))
            .put("streamSettings", stream)
        if (mobile && s.network == "ws") {
            out.put("mux", JSONObject().put("enabled", true).put("concurrency", 8).put("xudpConcurrency", 16).put("xudpProxyUDP443", "reject"))
        }
        return out
    }

    /** Из введённого текста («site.com, https://a.b/c», по строкам или через запятую) делает правила domain:… */
    fun cleanDomains(text: String): List<String> = text.lowercase().split(Regex("[\\s,;]+"))
        .map { it.removePrefix("https://").removePrefix("http://").removePrefix("www.").substringBefore("/").substringBefore(":").trim('.') }
        .filter { it.matches(Regex("[a-z0-9-]+(\\.[a-z0-9-]+)+")) }.distinct().take(200)

    private fun routing(mode: RouteMode, adblock: Boolean, mobile: Boolean = false, viaVpn: List<String> = emptyList(), direct: List<String> = emptyList(), countries: List<String> = emptyList(), compat: Boolean = false): JSONObject {
        val rules = JSONArray()
        if (!compat) {
            // DNS-запросы самого Xray: к Яндекс DNS — напрямую, все остальные — через VPN (их нельзя подменить)
            rules.put(rule("direct").put("inboundTag", JSONArray(listOf("dns-in"))).put("ip", JSONArray(listOf("77.88.8.8"))))
            rules.put(rule("proxy").put("inboundTag", JSONArray(listOf("dns-in"))))
        }
        // IPv6 не используем (в любом режиме): у части наших серверов (например, основной узел) нет выхода в IPv6, и Google, Cloudflare и другие
        // сначала шли туда, получали отказ с сервера и оставались «офлайн». Отказ на самом телефоне занимает миллисекунды, приложения берут IPv4,
        // и ничего не утекает в обход VPN. Берём именно 2000::/3 (все глобальные адреса), а не ::/0: так правило заведомо не заденет IPv4.
        rules.put(rule("block").put("ip", JSONArray(listOf("2000::/3"))))
        if (adblock) rules.put(rule("block").put("domain", JSONArray(listOf("geosite:category-ads-all"))))
        // Мобильный режим: QUIC (UDP 443) блокируем, чтобы браузеры и приложения перешли на TCP —
        // он стабильнее на мобильных сетях с потерями и нередко быстрее
        if (mobile) rules.put(rule("block").put("network", "udp").put("port", "443"))
        // Свои списки пользователя важнее любого режима
        if (viaVpn.isNotEmpty()) rules.put(rule("proxy").put("domain", JSONArray(viaVpn.map { "domain:$it" })))
        if (direct.isNotEmpty()) rules.put(rule("direct").put("domain", JSONArray(direct.map { "domain:$it" })))
        rules.put(rule("proxy").put("domain", JSONArray(ALWAYS_VPN)))
        // Выбранные страны (банки, сервисы, государственные сайты) идут напрямую: и по домену страны, и по её диапазонам IP
        val known = countries.filter { c -> COUNTRIES.any { it.first == c } }
        if (known.isNotEmpty()) {
            rules.put(rule("direct").put("domain", JSONArray(known.map { "domain:$it" })))
            rules.put(rule("direct").put("ip", JSONArray(known.map { "geoip:$it" })))
        }
        // Локальные адреса всегда напрямую
        rules.put(rule("direct").put("ip", JSONArray(listOf("geoip:private"))))
        when (mode) {
            RouteMode.RU_DIRECT -> {
                // Российские сайты — напрямую, остальное — через VPN
                rules.put(rule("direct").put("domain", JSONArray(RU_DOMAINS)))
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
        // AsIs: имя сайта не превращаем в адрес только ради выбора пути, иначе подменённый ответ DNS отправил бы сайт мимо VPN
        return JSONObject().put("domainStrategy", if (compat) "IPIfNonMatch" else "AsIs").put("rules", rules)
    }

    private fun rule(outbound: String) = JSONObject().put("type", "field").put("outboundTag", outbound)
}
