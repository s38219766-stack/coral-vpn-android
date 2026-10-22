package com.coral.vpn

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

data class UserInfo(val expire: Long, val used: Long, val total: Long)

object Api {
    const val BASE = "https://coralsvobod.duckdns.org"
    const val BOT = "https://t.me/coralbypasses_vpn_bot"

    private fun call(method: String, url: String): String {
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
        val c = URL(url).openConnection() as HttpURLConnection
        c.connectTimeout = 10000
        c.readTimeout = 10000
        c.setRequestProperty("User-Agent", "CoralVPN/0.3")
        val body = c.inputStream.bufferedReader().readText()
        val info = c.getHeaderField("subscription-userinfo")?.let { parseUserInfo(it) }
        return Subscription.parse(body) to info
    }

    fun parseUserInfo(h: String): UserInfo {
        val m = h.split(";").map { it.trim().split("=") }.filter { it.size == 2 }
            .associate { it[0] to (it[1].toLongOrNull() ?: 0L) }
        return UserInfo(m["expire"] ?: 0, (m["upload"] ?: 0) + (m["download"] ?: 0), m["total"] ?: 0)
    }
}
