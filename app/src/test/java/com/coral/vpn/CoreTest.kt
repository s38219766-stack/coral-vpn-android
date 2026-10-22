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

    @Test fun adblockAddsBlockRuleFirst() {
        val c = JSONObject(XrayConfig.build(Subscription.parseVless(reality), RouteMode.ALL, adblock = true))
        val first = c.getJSONObject("routing").getJSONArray("rules").getJSONObject(0)
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
        val first = rules.getJSONObject(0)
        assertEquals("block", first.getString("outboundTag"))
        assertEquals("443", first.getString("port"))
        assertEquals("udp", first.getString("network"))
        val sock = c.getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings").getJSONObject("sockopt")
        assertEquals(30, sock.getInt("tcpKeepAliveInterval"))
        val plain = JSONObject(XrayConfig.build(Subscription.parseVless(ws), RouteMode.ALL)).getJSONObject("routing").getJSONArray("rules")
        assertFalse(plain.toString().contains("\"port\":\"443\""))
    }
}
