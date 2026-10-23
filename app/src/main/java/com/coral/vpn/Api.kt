package com.coral.vpn

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

data class UserInfo(val expire: Long, val used: Long, val total: Long)

object Api {
    const val BASE = "https://coralsvobod.duckdns.org"
    const val BOT = "https://t.me/coralbypasses_vpn_bot"

    /** Основной домен и запасные (запоминаются из /api/mirrors). Любой запрос пробует их по очереди. */
    @Volatile var hosts: List<String> = listOf(URL(BASE).host)

    fun setMirrors(list: List<String>) {
        val main = URL(BASE).host
        hosts = (listOf(main) + list.filter { it != main && it.matches(Regex("[a-z0-9.-]+")) }).distinct()
    }

    /** Тот же адрес на каждом из доменов, основной первым. */
    fun candidates(url: String): List<String> {
        val u = URL(url)
        return hosts.map { h -> if (h == u.host) url else URL(u.protocol, h, u.port, u.file).toString() }.distinct()
    }

    private fun <T> firstOk(url: String, f: (String) -> T): T {
        var last: Throwable? = null
        for (c in candidates(url)) {
            try { return f(c) } catch (e: Exception) { last = e }
        }
        throw last ?: IllegalStateException("no hosts")
    }

    fun fetchMirrors(): List<String> = JSONObject(call("GET", "$BASE/api/mirrors")).getJSONArray("domains").let { a -> List(a.length()) { a.getString(it) } }

    private fun call(method: String, url: String): String = firstOk(url) { callOne(method, it) }

    private fun callOne(method: String, url: String): String {
        val c = URL(url).openConnection() as HttpURLConnection
        c.requestMethod = method
        c.connectTimeout = 10000
        c.readTimeout = 10000
        if (method == "POST") { c.doOutput = true; c.outputStream.use { it.write(ByteArray(0)) } }
        return c.inputStream.bufferedReader().readText() // на 4xx бросает исключение
    }

    /** Возвращает (токен, ссылка на бота для подтверждения). */
    fun startLogin(): Pair<String, String> {
        val j = JSONObject(call("POST", "$BASE/api/app/login/start"))
        return j.getString("token") to j.getString("url")
    }

    fun poll(token: String): JSONObject = JSONObject(call("GET", "$BASE/api/app/login/poll?token=$token"))

    /** Загружает подписку: список серверов и сведения об аккаунте из заголовка. */
    fun fetchSubscription(url: String): Pair<List<Server>, UserInfo?> {
        val (body, header) = fetchRaw(url)
        return Subscription.parse(body) to header?.let { parseUserInfo(it) }
    }

    /** Сырой ответ подписки и заголовок с остатком трафика — их же кладём в кэш. */
    fun fetchRaw(url: String): Pair<String, String?> = firstOk(url) { u ->
        val c = URL(u).openConnection() as HttpURLConnection
        c.connectTimeout = 8000
        c.readTimeout = 10000
        c.setRequestProperty("User-Agent", "CoralVPN/0.5")
        val body = c.inputStream.bufferedReader().readText()
        body to c.getHeaderField("subscription-userinfo")
    }

    fun parseUserInfo(h: String): UserInfo {
        val m = h.split(";").map { it.trim().split("=") }.filter { it.size == 2 }
            .associate { it[0] to (it[1].toLongOrNull() ?: 0L) }
        return UserInfo(m["expire"] ?: 0, (m["upload"] ?: 0) + (m["download"] ?: 0), m["total"] ?: 0)
    }
}
