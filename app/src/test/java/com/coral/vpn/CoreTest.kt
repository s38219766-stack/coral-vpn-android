package com.coral.vpn

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.util.Base64

class CoreTest {
    private val ws = "vless://11111111-2222-3333-4444-555555555555@coralsvobod.duckdns.org:443?security=tls&type=ws&headerType=&path=%2F8600d4756619&host=coralsvobod.duckdns.org&sni=coralsvobod.duckdns.org&fp=chrome&alpn=http%2F1.1#%F0%9F%9A%80%20Marz%20%28tg1%29%20%5BVLESS%20-%20ws%5D"
    private val reality = "vless://11111111-2222-3333-4444-555555555555@146.103.25.67:443?security=reality&type=tcp&headerType=&flow=xtls-rprx-vision&path=&host=&sni=coralsvobod.duckdns.org&fp=chrome&pbk=oISxSJtXPf6uQs9UetFaUx4qj3az86NUQZaiGK-b9Ec&sid=dff8cd0c43e2e7d3#Reality"

    @Test fun parsesBase64SubscriptionWithTwoServers() {
        val body = Base64.getEncoder().encodeToString("$ws\n$reality".toByteArray())
        val list = Subscription.parse(body)
        assertEquals(2, list.size)
        assertEquals("ws", list[0].network)
        assertEquals("/8600d4756619", list[0].path)
        assertEquals("tls", list[0].security)
        assertEquals("reality", list[1].security)
        assertEquals("xtls-rprx-vision", list[1].flow)
        assertEquals("dff8cd0c43e2e7d3", list[1].shortId)
    }

    @Test fun parsesPlainLinks() {
        assertEquals(1, Subscription.parse(reality).size)
    }

    @Test fun ignoresGarbage() {
        assertTrue(Subscription.parse("not a subscription").isEmpty())
    }

    @Test fun buildsWsConfig() {
        val c = JSONObject(XrayConfig.build(Subscription.parseVless(ws), RouteMode.ALL))
        val out = c.getJSONArray("outbounds").getJSONObject(0)
        assertEquals("vless", out.getString("protocol"))
        val st = out.getJSONObject("streamSettings")
        assertEquals("ws", st.getString("network"))
        assertEquals("/8600d4756619", st.getJSONObject("wsSettings").getString("path"))
        assertEquals("tls", st.getString("security"))
    }

    @Test fun buildsRealityConfigWithRuDirect() {
        val c = JSONObject(XrayConfig.build(Subscription.parseVless(reality), RouteMode.RU_DIRECT))
        val st = c.getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings")
        assertEquals("oISxSJtXPf6uQs9UetFaUx4qj3az86NUQZaiGK-b9Ec", st.getJSONObject("realitySettings").getString("publicKey"))
        val rules = c.getJSONObject("routing").getJSONArray("rules")
        assertTrue(rules.toString().contains("geoip:ru"))
        assertEquals("proxy", rules.getJSONObject(rules.length() - 1).getString("outboundTag"))
    }

    @Test fun allModeHasNoRuRules() {
        val c = JSONObject(XrayConfig.build(Subscription.parseVless(reality), RouteMode.ALL))
        assertFalse(c.getJSONObject("routing").toString().contains("geoip:ru"))
    }

    @Test fun parsesUserInfoHeader() {
        val i = Api.parseUserInfo("upload=100; download=900; total=0; expire=1824147360")
        assertEquals(1000L, i.used)
        assertEquals(1824147360L, i.expire)
    }

    @Test fun serverTitles() {
        assertEquals("Защищённый", Subscription.parseVless(ws).title())
        assertEquals("Быстрый", Subscription.parseVless(reality).title())
    }

    /** Первые два правила — служебные, для DNS самого Xray: дальше идут правила пользователя, рекламы и режима. */
    private val DNS_RULES = 3

    @Test fun dnsGoesThroughProxyAndRoutingNeverResolvesNames() {
        for (mode in RouteMode.values()) {
            val c = JSONObject(XrayConfig.build(Subscription.parseVless(reality), mode))
            val r = c.getJSONObject("routing")
            assertEquals("AsIs", r.getString("domainStrategy"))   // подменённый DNS не должен решать, идёт ли сайт напрямую
            val dns = c.getJSONObject("dns")
            assertEquals("dns-in", dns.getString("tag"))
            assertTrue(dns.toString().contains("https://1.1.1.1/dns-query"))
            val rules = r.getJSONArray("rules")
            assertEquals("dns-in", rules.getJSONObject(1).getJSONArray("inboundTag").getString(0))
            assertEquals("proxy", rules.getJSONObject(1).getString("outboundTag"))
        }
        // Яндекс DNS для российских доменов только в режиме «российское напрямую»
        assertTrue(JSONObject(XrayConfig.build(Subscription.parseVless(reality), RouteMode.RU_DIRECT)).getJSONObject("dns").toString().contains("77.88.8.8"))
        assertFalse(JSONObject(XrayConfig.build(Subscription.parseVless(reality), RouteMode.ALL)).getJSONObject("dns").toString().contains("77.88.8.8"))
    }

    @Test fun ipv6TrafficIsRefusedOnThePhoneNotSentToServers() {
        for (mode in RouteMode.values()) {
            val c = JSONObject(XrayConfig.build(Subscription.parseVless(reality), mode))
            val rules = c.getJSONObject("routing").getJSONArray("rules")
            val r = rules.getJSONObject(2)
            assertEquals("block", r.getString("outboundTag"))
            assertTrue(r.toString().contains("::/0"))
            assertFalse(c.getJSONArray("outbounds").toString().contains("dns-out"))
        }
    }

    @Test fun compatModeRestoresOldRouting() {
        val c = JSONObject(XrayConfig.build(Subscription.parseVless(reality), RouteMode.RU_DIRECT, compat = true))
        assertEquals("IPIfNonMatch", c.getJSONObject("routing").getString("domainStrategy"))
        val rules = c.getJSONObject("routing").getJSONArray("rules").toString()
        assertFalse(rules.contains("dns-in"))
        assertFalse(rules.contains("::/0"))
        assertFalse(c.getJSONObject("dns").has("tag"))
        assertTrue(c.getJSONObject("dns").toString().contains("1.1.1.1"))
    }

    @Test fun googleAndAiServicesAlwaysGoThroughVpnBeforeAnyDirectRule() {
        for (compat in listOf(true, false)) {
            val rules = JSONObject(XrayConfig.build(Subscription.parseVless(reality), RouteMode.RU_DIRECT, compat = compat)).getJSONObject("routing").getJSONArray("rules")
            fun idx(part: String) = (0 until rules.length()).first { rules.getJSONObject(it).toString().contains(part) }
            val ai = idx("gemini.google.com")
            assertEquals("proxy", rules.getJSONObject(ai).getString("outboundTag"))
            assertTrue("правило для Gemini должно стоять выше российских правил", ai < idx("geoip:ru") && ai < idx("geosite:category-ru"))
        }
    }

    @Test fun adblockAddsBlockRuleFirst() {
        val c = JSONObject(XrayConfig.build(Subscription.parseVless(reality), RouteMode.ALL, adblock = true))
        val first = c.getJSONObject("routing").getJSONArray("rules").getJSONObject(DNS_RULES)
        assertEquals("block", first.getString("outboundTag"))
        assertTrue(first.toString().contains("category-ads-all"))
    }

    @Test fun blockedModeDefaultsToDirect() {
        val rules = JSONObject(XrayConfig.build(Subscription.parseVless(reality), RouteMode.BLOCKED)).getJSONObject("routing").getJSONArray("rules")
        assertEquals("direct", rules.getJSONObject(rules.length() - 1).getString("outboundTag"))
        assertTrue(rules.toString().contains("geosite:youtube"))
    }

    private val xhttp = "vless://11111111-2222-3333-4444-555555555555@coralsvobod.duckdns.org:443?security=tls&type=xhttp&headerType=&path=%2Fxh123&host=coralsvobod.duckdns.org&mode=packet-up&extra=%7B%22scMaxEachPostBytes%22%3A+1000000%2C+%22xPaddingBytes%22%3A+%22100-1000%22%2C+%22noGRPCHeader%22%3A+false%7D&sni=coralsvobod.duckdns.org&fp=chrome&alpn=h2#x"

    @Test fun parsesAndBuildsXhttp() {
        val s = Subscription.parseVless(xhttp)
        assertEquals("xhttp", s.network)
        assertEquals("packet-up", s.mode)
        val st = JSONObject(XrayConfig.build(s, RouteMode.ALL)).getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings")
        val xs = st.getJSONObject("xhttpSettings")
        assertEquals("/xh123", xs.getString("path"))
        assertEquals("packet-up", xs.getString("mode"))
        assertEquals("100-1000", xs.getJSONObject("extra").getString("xPaddingBytes"))
        assertEquals("Запасной (XHTTP)", s.title())
    }

    @Test fun mobileModeAddsMuxOnlyForWs() {
        val wsOut = JSONObject(XrayConfig.build(Subscription.parseVless(ws), RouteMode.ALL, mobile = true)).getJSONArray("outbounds").getJSONObject(0)
        assertTrue(wsOut.getJSONObject("mux").getBoolean("enabled"))
        assertTrue(wsOut.getJSONObject("streamSettings").getJSONObject("sockopt").getBoolean("tcpNoDelay"))
        val reOut = JSONObject(XrayConfig.build(Subscription.parseVless(reality), RouteMode.ALL, mobile = true)).getJSONArray("outbounds").getJSONObject(0)
        assertFalse(reOut.has("mux"))
        val plain = JSONObject(XrayConfig.build(Subscription.parseVless(ws), RouteMode.ALL)).getJSONArray("outbounds").getJSONObject(0)
        assertFalse(plain.has("mux"))
    }

    @Test fun mobileModeBlocksQuicAndKeepsAlive() {
        val c = JSONObject(XrayConfig.build(Subscription.parseVless(ws), RouteMode.ALL, mobile = true))
        val rules = c.getJSONObject("routing").getJSONArray("rules")
        val first = rules.getJSONObject(DNS_RULES)
        assertEquals("block", first.getString("outboundTag"))
        assertEquals("443", first.getString("port"))
        assertEquals("udp", first.getString("network"))
        val sock = c.getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings").getJSONObject("sockopt")
        assertEquals(30, sock.getInt("tcpKeepAliveInterval"))
        val plain = JSONObject(XrayConfig.build(Subscription.parseVless(ws), RouteMode.ALL)).getJSONObject("routing").getJSONArray("rules")
        assertFalse(plain.toString().contains("\"port\":\"443\""))
    }

    @Test fun transportKeysMatchServerNames() {
        assertEquals("ws", Subscription.parseVless(ws).transportKey())
        assertEquals("reality", Subscription.parseVless(reality).transportKey())
        assertEquals("reality_ip", Subscription.parseVless(reality.replace(":443?", ":8443?")).transportKey())
    }

    @Test fun mirrorsKeepPathAndPutMainFirst() {
        Api.setMirrors(listOf("backup.example.com", "bad host!", "coralsvobod.duckdns.org"))
        val c = Api.candidates("https://coralsvobod.duckdns.org/sub/abc123")
        assertEquals(listOf("https://coralsvobod.duckdns.org/sub/abc123", "https://backup.example.com/sub/abc123"), c)
        Api.setMirrors(emptyList())
    }

    @Test fun fragmentAddsDialerProxyAndFreedomOutbound() {
        val on = JSONObject(XrayConfig.build(Subscription.parseVless(reality), RouteMode.ALL, fragment = true))
        val outs = on.getJSONArray("outbounds")
        assertEquals("fragment", outs.getJSONObject(0).getJSONObject("streamSettings").getJSONObject("sockopt").getString("dialerProxy"))
        val frag = (0 until outs.length()).map { outs.getJSONObject(it) }.first { it.getString("tag") == "fragment" }
        assertEquals("tlshello", frag.getJSONObject("settings").getJSONObject("fragment").getString("packets"))
        val off = JSONObject(XrayConfig.build(Subscription.parseVless(reality), RouteMode.ALL))
        assertFalse(off.getJSONArray("outbounds").toString().contains("fragment"))
        // вместе с мобильным режимом настройки сокета не затирают друг друга
        val both = JSONObject(XrayConfig.build(Subscription.parseVless(ws), RouteMode.ALL, mobile = true, fragment = true))
        val sock = both.getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings").getJSONObject("sockopt")
        assertTrue(sock.getBoolean("tcpNoDelay")); assertEquals("fragment", sock.getString("dialerProxy"))
    }

    @Test fun bankAppsAreRecognized() {
        assertTrue(AppRules.isBank("ru.sberbankmobile", "СберБанк Онлайн"))
        assertTrue(AppRules.isBank("com.idamob.tinkoff.android", "Тинькофф"))
        assertTrue(AppRules.isBank("ru.rostel", "Госуслуги"))
        assertTrue(AppRules.isBank("some.unknown.pkg", "Банк Открытие"))   // по названию
        assertFalse(AppRules.isBank("org.telegram.messenger", "Telegram"))
        assertFalse(AppRules.isBank("com.whatsapp", "WhatsApp"))
    }

    @Test fun russianAppsDetectedByPrefixOrName() {
        assertTrue(AppRules.isRussian("com.yandex.browser", "Яндекс Браузер"))
        assertTrue(AppRules.isRussian("com.vkontakte.android", "VK"))
        assertTrue(AppRules.isRussian("ru.ozon.app.android", "Ozon"))
        assertFalse(AppRules.isRussian("com.google.android.youtube", "YouTube"))
        val apps = listOf("ru.rostel" to "Госуслуги", "com.whatsapp" to "WhatsApp")
        assertEquals(setOf("ru.rostel"), AppRules.russian(apps))
    }

    @Test fun ruDirectKnowsRussianServicesAndRoutesBySniffedDomain() {
        val c = JSONObject(XrayConfig.build(Subscription.parseVless(reality), RouteMode.RU_DIRECT))
        val rules = c.getJSONObject("routing").getJSONArray("rules").toString()
        for (x in listOf("geosite:category-ru", "geosite:yandex", "geosite:vk", "domain:sberbank.com", "domain:userapi.com", "geoip:ru")) assertTrue(x, rules.contains(x))
        val sniff = c.getJSONArray("inbounds").getJSONObject(0).getJSONObject("sniffing")
        assertTrue(sniff.getBoolean("routeOnly"))
    }

    @Test fun customSitesAreCleanedAndComeFirst() {
        assertEquals(listOf("example.com", "bank.ru", "a-b.org"), XrayConfig.cleanDomains("https://www.Example.com/path, bank.ru:443\n a-b.org; junk ../x"))
        val c = JSONObject(XrayConfig.build(Subscription.parseVless(reality), RouteMode.RU_DIRECT, viaVpn = listOf("example.com"), direct = listOf("bank.ru")))
        val rules = c.getJSONObject("routing").getJSONArray("rules")
        assertEquals("proxy", rules.getJSONObject(DNS_RULES).getString("outboundTag"))
        assertTrue(rules.getJSONObject(DNS_RULES).toString().contains("domain:example.com"))
        assertEquals("direct", rules.getJSONObject(DNS_RULES + 1).getString("outboundTag"))
        assertTrue(rules.getJSONObject(DNS_RULES + 1).toString().contains("domain:bank.ru"))
    }

    @Test fun russianBridgeServerIsRecognized() {
        val ru = Subscription.parseVless(reality.replace("146.103.25.67", "155.212.139.252").replace("#Reality", "#Coral%20RU%20%28tg1%29"))
        assertEquals("reality_ru", ru.transportKey())
        assertEquals("Через Россию", ru.title())
    }

    @Test fun countriesGoDirectByDomainAndIp() {
        val c = JSONObject(XrayConfig.build(Subscription.parseVless(reality), RouteMode.ALL, countries = listOf("kz", "ge", "xx")))
        val rules = c.getJSONObject("routing").getJSONArray("rules").toString()
        for (x in listOf("domain:kz", "domain:ge", "geoip:kz", "geoip:ge")) assertTrue(x, rules.contains(x))
        assertFalse("неизвестная страна не попадает в правила", rules.contains("xx"))
        val none = JSONObject(XrayConfig.build(Subscription.parseVless(reality), RouteMode.ALL)).getJSONObject("routing").toString()
        assertFalse(none.contains("geoip:kz"))
    }

    private val extraJson = """{"servers":[
        {"kind":"hysteria2","name":"Быстрый UDP (Hysteria2)","host":"203.0.113.5","port":443,"password":"pw1","sni":"example.org"},
        {"kind":"shadowtls","name":"Маска TLS (Shadow-TLS)","host":"203.0.113.5","port":8853,"password":"pw2","sni":"www.yandex.ru","ss_method":"2022-blake3-aes-128-gcm","ss_password":"a:b"},
        {"kind":"unknown","name":"x","host":"h","port":1,"password":"p"}]}"""

    @Test fun extraServersParsedAndUnknownIgnored() {
        val list = Subscription.parseExtra(extraJson)
        assertEquals(2, list.size)
        assertEquals("hysteria2", list[0].transportKey())
        assertEquals("shadowtls", list[1].transportKey())
        assertEquals("Быстрый UDP (Hysteria2)", list[0].title())
        assertTrue(Subscription.parseExtra("{}").isEmpty())
    }

    @Test fun singBoxConfigsForBothTransports() {
        val (hy, st) = Subscription.parseExtra(extraJson)
        val h = JSONObject(SingBoxConfig.build(hy)!!)
        assertEquals("hysteria2", h.getJSONArray("outbounds").getJSONObject(0).getString("type"))
        assertEquals(SingBoxConfig.SOCKS_PORT, h.getJSONArray("inbounds").getJSONObject(0).getInt("listen_port"))
        val s = JSONObject(SingBoxConfig.build(st)!!)
        val outs = s.getJSONArray("outbounds")
        assertEquals("shadowtls", outs.getJSONObject(0).getString("type"))
        assertEquals("stls", outs.getJSONObject(1).getString("detour"))
        assertEquals("out", s.getJSONObject("route").getString("final"))
        assertNull(SingBoxConfig.build(Subscription.parseVless(reality)))
    }

    @Test fun tuicServerParsedAndConfigured() {
        val json = """{"servers":[{"kind":"tuic","name":"Запасной UDP (TUIC)","host":"203.0.113.5","port":4443,"uuid":"11111111-2222-3333-4444-555555555555","password":"pw3","sni":"example.org"}]}"""
        val t = Subscription.parseExtra(json).single()
        assertEquals("tuic", t.transportKey())
        val o = JSONObject(SingBoxConfig.build(t)!!).getJSONArray("outbounds").getJSONObject(0)
        assertEquals("tuic", o.getString("type"))
        assertEquals("11111111-2222-3333-4444-555555555555", o.getString("uuid"))
        assertEquals("pw3", o.getString("password"))
        assertEquals(4443, o.getInt("server_port"))
    }

    @Test fun hysteria2PortHoppingAndPlainShadowsocks() {
        val json = """{"servers":[
            {"kind":"hysteria2","name":"h","host":"203.0.113.5","port":443,"password":"pw","sni":"example.org","ports":"20000:30000"},
            {"kind":"ss2022","name":"s","host":"203.0.113.5","port":8388,"password":"a:b","ss_method":"2022-blake3-aes-128-gcm"}]}"""
        val (hy, ss) = Subscription.parseExtra(json)
        val h = JSONObject(SingBoxConfig.build(hy)!!).getJSONArray("outbounds").getJSONObject(0)
        assertEquals("20000:30000", h.getJSONArray("server_ports").getString(0))
        assertEquals("30s", h.getString("hop_interval"))
        assertEquals("ss2022", ss.transportKey())
        val o = JSONObject(SingBoxConfig.build(ss)!!).getJSONArray("outbounds").getJSONObject(0)
        assertEquals("shadowsocks", o.getString("type"))
        assertEquals(8388, o.getInt("server_port"))
        assertEquals("a:b", o.getString("password"))
    }

    /** Ровно та форма ответа, которую отдаёт сервер (backend/app/transports.py, extra): ни один сервер не должен потеряться при разборе. */
    @Test fun serverExtraShapeParsesAllFiveKinds() {
        val json = """{"servers":[
            {"kind":"hysteria2","name":"Быстрый UDP (Hysteria2)","host":"203.0.113.5","port":443,"password":"p1","sni":"example.org","ports":"20000:30000"},
            {"kind":"ss2022","name":"Простой TCP (Shadowsocks)","host":"203.0.113.5","port":8388,"password":"a:b","ss_method":"2022-blake3-aes-128-gcm"},
            {"kind":"tuic","name":"Запасной UDP (TUIC)","host":"203.0.113.5","port":4443,"uuid":"11111111-2222-3333-4444-555555555555","password":"p3","sni":"example.org"},
            {"kind":"ct","name":"Наш протокол (Coral)","host":"203.0.113.5,203.0.113.6","ports":"21000:21999","ct_key":"abcd","ss_method":"2022-blake3-aes-128-gcm","password":"a:b"},
            {"kind":"shadowtls","name":"Маска TLS (Shadow-TLS)","host":"203.0.113.5","port":8853,"password":"p5","sni":"www.yandex.ru","ss_method":"2022-blake3-aes-128-gcm","ss_password":"a:b"}]}"""
        val list = Subscription.parseExtra(json)
        assertEquals(listOf("hysteria2", "ss2022", "tuic", "ct", "shadowtls"), list.map { it.transportKey() })
        list.forEach { assertNotNull("конфиг sing-box для ${it.kind}", SingBoxConfig.build(it)) }
        assertEquals("203.0.113.5,203.0.113.6|21000:21999|abcd", ctSpec(list[3]))
    }

    @Test fun coralTransportGoesThroughLocalCtClient() {
        val json = """{"servers":[{"kind":"ct","name":"Наш протокол (Coral)","host":"203.0.113.5","ports":"21000:21999","ct_key":"abcd","ss_method":"2022-blake3-aes-128-gcm","password":"a:b"}]}"""
        val c = Subscription.parseExtra(json).single()
        assertEquals("ct", c.transportKey())
        assertEquals("203.0.113.5|21000:21999|abcd", ctSpec(c))
        val o = JSONObject(SingBoxConfig.build(c)!!).getJSONArray("outbounds").getJSONObject(0)
        assertEquals("shadowsocks", o.getString("type"))
        assertEquals("127.0.0.1", o.getString("server"))
        assertEquals(SingBoxConfig.CT_PORT, o.getInt("server_port"))
        assertEquals("a:b", o.getString("password"))
        assertTrue("мультиплексирование включено", o.getJSONObject("multiplex").getBoolean("enabled"))
        assertEquals("", ctSpec(Subscription.parseVless(reality)))
    }

    @Test fun extraServersGoThroughLocalSocksInXray() {
        val hy = Subscription.parseExtra(extraJson)[0]
        val c = JSONObject(XrayConfig.build(hy, RouteMode.RU_DIRECT, fragment = true))
        val outs = c.getJSONArray("outbounds")
        val proxy = outs.getJSONObject(0)
        assertEquals("socks", proxy.getString("protocol"))
        assertEquals(SingBoxConfig.SOCKS_PORT, proxy.getJSONObject("settings").getJSONArray("servers").getJSONObject(0).getInt("port"))
        assertFalse("фрагментация не нужна: шифрование делает sing-box", outs.toString().contains("fragment"))
    }

    @Test fun finlandNodeIsRecognized() {
        val fi = Subscription.parseVless(reality.replace("146.103.25.67", "13.140.95.212").replace(":443?", ":8443?").replace("#Reality", "#Coral%20FI%20%28tg1%29"))
        assertEquals("reality_fi", fi.transportKey())
        assertEquals("Финляндия", fi.title())
    }

    @Test fun secondFinlandNodeHasOwnTitleButSameKey() {
        val fi2 = Subscription.parseVless(reality.replace("146.103.25.67", "13.140.95.197").replace(":443?", ":8443?").replace("#Reality", "#Coral%20FI2%20%28tg1%29"))
        assertEquals("Финляндия 2", fi2.title())
        assertEquals("reality_fi", fi2.transportKey())
    }
}
