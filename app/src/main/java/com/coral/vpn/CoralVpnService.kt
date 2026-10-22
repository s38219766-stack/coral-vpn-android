package com.coral.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import kotlinx.coroutines.flow.MutableStateFlow
import org.json.JSONObject
import java.io.File
import java.net.Inet4Address
import java.net.InetAddress

enum class VpnState { OFF, CONNECTING, ON, ERROR }

class CoralVpnService : VpnService() {
    companion object {
        const val ACTION_STOP = "com.coral.vpn.STOP"
        const val EXTRA_CONFIGS = "configs"
        const val EXTRA_NAMES = "names"
        const val EXTRA_APPS = "apps"
        val state = MutableStateFlow(VpnState.OFF)
        val message = MutableStateFlow("")
    }

    private var tun: ParcelFileDescriptor? = null
    private var xray: Process? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) { shutdown(); return START_NOT_STICKY }
        val configs = intent?.getStringArrayExtra(EXTRA_CONFIGS)?.toList() ?: return START_NOT_STICKY
        val names = intent.getStringArrayExtra(EXTRA_NAMES)?.toList().orEmpty()
        val apps = intent.getStringArrayExtra(EXTRA_APPS)?.toList().orEmpty()
        Diag.clear()
        Diag.log("onStartCommand, приложений в списке: ${apps.size}")
        startForegroundCompat()
        state.value = VpnState.CONNECTING
        message.value = "Подключение…"
        Thread { runCatching { start(configs, names, apps) }.onFailure { fail(it) } }.start()
        return START_NOT_STICKY
    }

    private fun start(configs: List<String>, names: List<String>, apps: List<String>) {
        Diag.log("шаг 1: копирование geoip/geosite")
        val assets = File(filesDir, "xray-assets").apply { mkdirs() }
        for (name in listOf("geoip.dat", "geosite.dat")) {
            val out = File(assets, name)
            if (!out.exists()) this.assets.open(name).use { i -> out.outputStream().use { o -> i.copyTo(o) } }
        }
        // Пробуем серверы по очереди, пока один не пропустит трафик
        var chosen: String? = null
        for ((i, config) in configs.withIndex()) {
            val label = names.getOrNull(i) ?: "сервер ${i + 1}"
            message.value = "Проверка: $label"
            Diag.log("шаг 2: сервер «$label»")
            val ok = runCatching { tryServer(config, assets) }.onFailure { Diag.log("ошибка: ${it.message}") }.getOrDefault(false)
            if (ok) { chosen = label; break }
            xray?.destroy(); xray = null
            Diag.log("сервер «$label» не отвечает, пробуем следующий")
        }
        check(chosen != null) { "ни один сервер не отвечает" }
        Diag.log("шаг 3: выбран «$chosen»")

        val builder = Builder()
            .setSession("Coral VPN")
            .setMtu(8500)
            .addAddress("198.18.0.1", 32)
            .addRoute("0.0.0.0", 0)
            .addAddress("fc00::1", 128)
            .addRoute("::", 0)
            .addDnsServer("1.1.1.1")
        if (apps.isEmpty()) {
            builder.addDisallowedApplication(packageName) // иначе трафик самого Xray зациклится
        } else {
            apps.filter { it != packageName }.forEach { runCatching { builder.addAllowedApplication(it) } }
        }
        Diag.log("шаг 4: создание VPN-интерфейса")
        val fd = builder.establish() ?: error("система не выдала VPN-интерфейс")
        tun = fd

        val hev = File(filesDir, "hev.yml")
        hev.writeText(
            """
            tunnel:
              mtu: 8500
              ipv4: 198.18.0.1
              ipv6: 'fc00::1'
            socks5:
              port: ${XrayConfig.SOCKS_PORT}
              address: 127.0.0.1
              udp: 'udp'
            misc:
              task-stack-size: 81920
              connect-timeout: 5000
              tcp-read-write-timeout: 300000
              udp-read-write-timeout: 60000
              log-level: warn
            """.trimIndent()
        )
        Diag.log("шаг 5: запуск туннеля hev, fd=${fd.fd}")
        check(TProxyService.TProxyStartService(hev.path, fd.fd)) { "туннель hev не запустился" }
        Diag.log("шаг 6: туннель запущен, работает=${TProxyService.TProxyIsRunning()}")
        state.value = VpnState.ON
        message.value = "Подключено: $chosen"
    }

    /** Запускает ядро с этим конфигом и проверяет, ходит ли трафик через сервер. */
    private fun tryServer(config: String, assets: File): Boolean {
        val cfg = File(filesDir, "config.json").apply { writeText(resolveServer(config)) }
        val bin = File(applicationInfo.nativeLibraryDir, "libxray.so")
        val pb = ProcessBuilder(bin.path, "run", "-c", cfg.path).redirectErrorStream(true)
        pb.environment()["XRAY_LOCATION_ASSET"] = assets.path
        val proc = pb.start()
        xray = proc
        Thread {
            var logged = 0
            runCatching {
                proc.inputStream.bufferedReader().forEachLine { line ->
                    if (!line.contains("accepted") && logged < 150) { Diag.log("xray: ${line.take(300)}"); logged++ }
                }
            }
        }.start()
        Thread.sleep(800)
        if (!proc.isAlive) return false
        return probe()
    }

    /** Запрос через локальный SOCKS ядра: 204 значит, сервер работает. */
    private fun probe(): Boolean {
        repeat(2) {
            runCatching {
                val proxy = java.net.Proxy(java.net.Proxy.Type.SOCKS, java.net.InetSocketAddress("127.0.0.1", XrayConfig.SOCKS_PORT))
                val c = java.net.URL("http://cp.cloudflare.com/generate_204").openConnection(proxy) as java.net.HttpURLConnection
                c.connectTimeout = 6000; c.readTimeout = 6000
                val code = c.responseCode
                c.disconnect()
                Diag.log("проверка связи: HTTP $code")
                if (code == 204) return true
            }.onFailure { Diag.log("проверка связи: ${it.message}") }
        }
        return false
    }

    /** У Xray на Android нет системного DNS (нет resolv.conf), поэтому подставляем IP сервера сами. */
    private fun resolveServer(config: String): String {
        val root = JSONObject(config)
        val vnext = root.getJSONArray("outbounds").getJSONObject(0)
            .getJSONObject("settings").getJSONArray("vnext").getJSONObject(0)
        val host = vnext.getString("address")
        if (host.any { it.isLetter() }) {
            val ip = InetAddress.getAllByName(host).filterIsInstance<Inet4Address>().firstOrNull()?.hostAddress
                ?: error("не удалось определить IP сервера $host")
            vnext.put("address", ip)
            Diag.log("сервер $host → $ip")
        }
        return root.toString()
    }

    private fun fail(e: Throwable) {
        Diag.log("ОШИБКА: ${e}")
        message.value = e.message ?: e.toString()
        shutdown()
        state.value = VpnState.ERROR
    }

    private fun shutdown() {
        runCatching { TProxyService.TProxyStopService() }
        xray?.destroy(); xray = null
        runCatching { tun?.close() }; tun = null
        if (state.value != VpnState.ERROR) state.value = VpnState.OFF
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onRevoke() = shutdown()
    override fun onDestroy() { shutdown(); super.onDestroy() }

    private fun startForegroundCompat() {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel("vpn", "VPN", NotificationManager.IMPORTANCE_LOW))
        val n: Notification = Notification.Builder(this, "vpn")
            .setContentTitle("Coral VPN").setContentText("Защита включена")
            .setSmallIcon(android.R.drawable.ic_lock_lock).setOngoing(true).build()
        if (Build.VERSION.SDK_INT >= 34) startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        else startForeground(1, n)
    }
}
