package com.coral.vpn

import org.json.JSONArray
import org.json.JSONObject

/** Клиентская конфигурация sing-box для Hysteria2, TUIC и Shadow-TLS. Ядро слушает локальный SOCKS, к нему подключается Xray. */
object SingBoxConfig {
    const val SOCKS_PORT = 10809
    const val CT_PORT = 19500   // локальный порт ct-client (Coral Transport): sing-box отдаёт Shadowsocks ему

    fun build(s: Server): String? {
        val outbounds = JSONArray()
        val final: String
        when (s.kind) {
            "hysteria2" -> {
                val hy = JSONObject().put("type", "hysteria2").put("tag", "out")
                    .put("server", s.host).put("server_port", s.port).put("password", s.secret)
                    .put("tls", JSONObject().put("enabled", true).put("server_name", s.sni).put("alpn", JSONArray(listOf("h3"))))
                // Прыжки по портам: оператору сложнее резать один UDP-порт
                if (s.ports.matches(Regex("\\d+:\\d+"))) hy.put("server_ports", JSONArray(listOf(s.ports))).put("hop_interval", "30s")
                outbounds.put(hy)
                final = "out"
            }
            "ct" -> {
                // Shadowsocks-2022 идёт не на сервер, а на локальный ct-client, который меняет форму трафика
                // Мультиплексирование: много потоков в нескольких соединениях, новый сайт открывается без нового рукопожатия
                outbounds.put(JSONObject().put("type", "shadowsocks").put("tag", "out")
                    .put("server", "127.0.0.1").put("server_port", CT_PORT).put("method", s.ssMethod).put("password", s.secret)
                    .put("multiplex", JSONObject().put("enabled", true).put("protocol", "smux").put("max_connections", 4).put("min_streams", 4)))
                final = "out"
            }
            "ss2022" -> {
                outbounds.put(JSONObject().put("type", "shadowsocks").put("tag", "out")
                    .put("server", s.host).put("server_port", s.port).put("method", s.ssMethod).put("password", s.secret))
                final = "out"
            }
            "tuic" -> {
                outbounds.put(JSONObject().put("type", "tuic").put("tag", "out")
                    .put("server", s.host).put("server_port", s.port).put("uuid", s.uuid).put("password", s.secret)
                    .put("congestion_control", "bbr")
                    .put("tls", JSONObject().put("enabled", true).put("server_name", s.sni).put("alpn", JSONArray(listOf("h3")))))
                final = "out"
            }
            "shadowtls" -> {
                outbounds.put(JSONObject().put("type", "shadowtls").put("tag", "stls")
                    .put("server", s.host).put("server_port", s.port).put("version", 3).put("password", s.secret)
                    .put("tls", JSONObject().put("enabled", true).put("server_name", s.sni)))
                outbounds.put(JSONObject().put("type", "shadowsocks").put("tag", "out").put("detour", "stls")
                    .put("method", s.ssMethod).put("password", s.ssPassword))
                final = "out"
            }
            else -> return null
        }
        return JSONObject()
            .put("log", JSONObject().put("level", "warn"))
            .put("inbounds", JSONArray().put(JSONObject().put("type", "socks").put("tag", "in").put("listen", "127.0.0.1").put("listen_port", SOCKS_PORT)))
            .put("outbounds", outbounds)
            .put("route", JSONObject().put("final", final))
            .toString()
    }
}
