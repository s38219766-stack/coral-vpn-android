package com.coral.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.graphics.drawable.Icon
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
        const val ACTION_SWITCH = "com.coral.vpn.SWITCH"
        const val EXTRA_CONFIGS = "configs"
        const val EXTRA_NAMES = "names"
        const val EXTRA_APPS = "apps"
        const val EXTRA_APPS_MODE = "apps_mode"
        const val EXTRA_MOBILE = "mobile"
        const val EXTRA_KEYS = "keys"
        const val EXTRA_SB = "sb"
        const val EXTRA_CT = "ct"
        const val EXTRA_AUTO = "auto"
        val state = MutableStateFlow(VpnState.OFF)
        val message = MutableStateFlow("")
    }

    private var tun: ParcelFileDescriptor? = null
    private var xray: Process? = null
    private var singbox: Process? = null
    private var ct: Process? = null
    private var lists: Lists? = null
    @Volatile private var currentIdx = -1
    @Volatile private var switching = false
    @Volatile private var generation = 0   // меняется при остановке, чтобы сторож связи прекратил работу

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) { shutdown(); return START_NOT_STICKY }
        if (intent?.action == ACTION_SWITCH) { manualSwitch(); return START_NOT_STICKY }
        val configs = intent?.getStringArrayExtra(EXTRA_CONFIGS)?.toList() ?: return START_NOT_STICKY
        val names = intent.getStringArrayExtra(EXTRA_NAMES)?.toList().orEmpty()
        val apps = intent.getStringArrayExtra(EXTRA_APPS)?.toList().orEmpty()
        val appsMode = intent.getStringExtra(EXTRA_APPS_MODE) ?: if (apps.isEmpty()) "exclude" else "only"
        val mobile = intent.getBooleanExtra(EXTRA_MOBILE, false)
        val keys = intent.getStringArrayExtra(EXTRA_KEYS)?.toList().orEmpty()
        val auto = intent.getBooleanExtra(EXTRA_AUTO, false)
        val sb = intent.getStringArrayExtra(EXTRA_SB)?.toList().orEmpty()
        val cts = intent.getStringArrayExtra(EXTRA_CT)?.toList().orEmpty()
        Diag.clear()
        Diag.log("onStartCommand, приложений в списке: ${apps.size}, режим: $appsMode")
        startForegroundCompat()
        state.value = VpnState.CONNECTING
        message.value = "Подключение…"
        Thread { runCatching { start(configs, names, keys, sb, cts, auto, apps, appsMode, mobile) }.onFailure { fail(it) } }.start()
        return START_NOT_STICKY
    }

    private fun start(configs0: List<String>, names0: List<String>, keys0: List<String>, sb0: List<String>, ct0: List<String>, auto: Boolean, apps: List<String>, appsMode: String, mobile: Boolean) {
        val tStart = System.currentTimeMillis()
        val mtu = if (mobile) 1400 else 8500 // на мобильных сетях меньший MTU избавляет от потерь крупных пакетов
        Diag.log("шаг 1: копирование geoip/geosite")
        val assets = File(filesDir, "xray-assets").apply { mkdirs() }
        for (name in listOf("geoip.dat", "geosite.dat")) {
            val out = File(assets, name)
            if (!out.exists()) this.assets.open(name).use { i -> out.outputStream().use { o -> i.copyTo(o) } }
        }
        // «Авто»: ставим вперёд транспорты, которые у этого оператора сейчас работают чаще всего
        var configs = configs0; var names = names0; var keys = keys0
        var sbs = if (sb0.size == configs0.size) sb0 else configs0.map { "" }
        var cts = if (ct0.size == configs0.size) ct0 else configs0.map { "" }
        if (keys0.size == configs0.size && auto) {
            val best = NetProbe.best(this)
            if (best.isNotEmpty()) {
                val idx = configs0.indices.sortedBy { i -> best.indexOf(keys0[i]).let { if (it < 0) 99 else it } }
                configs = idx.map { configs0[it] }; names = idx.map { names0.getOrElse(it) { "" } }; keys = idx.map { keys0[it] }; sbs = idx.map { sb0.getOrElse(it) { "" } }; cts = idx.map { ct0.getOrElse(it) { "" } }
                Diag.log("порядок по статистике оператора: ${keys.joinToString()}")
            }
        }
        // Память этой сети: способ, который сработал здесь в прошлый раз, пробуем первым (работает и без связи с сервером)
        val net = if (NetProbe.isWifi(this)) "wifi" else NetProbe.carrier(this).ifBlank { "mobile" }
        val memory = getSharedPreferences("coral", MODE_PRIVATE)
        if (auto && keys.size == configs.size) {
            val last = memory.getString("last_ok_$net", null)
            val at = keys.indexOf(last)
            if (last != null && at > 0) {
                val order = listOf(at) + keys.indices.filter { it != at }
                configs = order.map { configs[it] }; names = order.map { names.getOrElse(it) { "" } }; keys = order.map { keys[it] }
                sbs = order.map { sbs.getOrElse(it) { "" } }; cts = order.map { cts.getOrElse(it) { "" } }
                Diag.log("первым — способ, сработавший в этой сети в прошлый раз: $last")
            }
        }
        // Пробуем серверы по очереди, пока один не пропустит трафик
        var chosen: String? = null
        var chosenIdx = -1
        for ((i, config) in configs.withIndex()) {
            val label = names.getOrNull(i) ?: "сервер ${i + 1}"
            message.value = "Проверка: $label"
            Diag.log("шаг 2: сервер «$label»")
            val t0 = System.currentTimeMillis()
            val ok = runCatching { tryServer(config, assets, sbConfig = sbs.getOrElse(i) { "" }, ctSpec = cts.getOrElse(i) { "" }) }.onFailure { Diag.log("ошибка: ${it.message}") }.getOrDefault(false)
            keys.getOrNull(i)?.let { NetProbe.report(this, it, ok, (System.currentTimeMillis() - t0).toInt()) }
            Diag.log("сервер «$label»: ${if (ok) "готов" else "не прошёл"} за ${System.currentTimeMillis() - t0} мс")
            if (ok) { chosen = label; chosenIdx = i; break }
            xray?.destroy(); xray = null
            singbox?.destroy(); singbox = null
            ct?.destroy(); ct = null
            Diag.log("сервер «$label» не отвечает, пробуем следующий")
        }
        if (chosen == null && configs.isNotEmpty()) {
            // Сама проверка могла ошибиться — не отказываем, а подключаемся к первому серверу как есть
            Diag.log("ни одна проверка не прошла — подключаемся к первому серверу без проверки")
            val ok = runCatching { tryServer(configs[0], assets, verify = false, sbConfig = sbs.getOrElse(0) { "" }, ctSpec = cts.getOrElse(0) { "" }) }.getOrDefault(false)
            if (ok) { chosen = (names.getOrNull(0) ?: "сервер 1") + " (без проверки)"; chosenIdx = 0 }
        }
        check(chosen != null) { "не удалось запустить ядро — отправьте журнал разработчику" }
        Diag.log("шаг 3: выбран «$chosen», всего ${System.currentTimeMillis() - tStart} мс")
        if (auto && chosenIdx >= 0 && chosen?.endsWith("(без проверки)") != true) keys.getOrNull(chosenIdx)?.let { memory.edit().putString("last_ok_$net", it).apply() }

        val builder = Builder()
            .setSession("Coral VPN")
            .setMtu(mtu)
            .addAddress("198.18.0.1", 32)
            .addRoute("0.0.0.0", 0)
            .addAddress("fc00::1", 128)
            .addRoute("::", 0)
            .addDnsServer("1.1.1.1")
        if (appsMode == "only" && apps.isNotEmpty()) {
            apps.filter { it != packageName }.forEach { runCatching { builder.addAllowedApplication(it) } }
        } else {
            builder.addDisallowedApplication(packageName) // иначе трафик самого Xray зациклится
            // Приложения из списка (банки, выбранные пользователем) вообще не попадают в туннель
            apps.filter { it != packageName }.forEach { runCatching { builder.addDisallowedApplication(it) } }
        }
        Diag.log("шаг 4: создание VPN-интерфейса")
        val fd = builder.establish() ?: error("система не выдала VPN-интерфейс")
        tun = fd

        val hev = File(filesDir, "hev.yml")
        hev.writeText(
            """
            tunnel:
              mtu: $mtu
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
        updateNotification("Защита включена · $chosen")
        lists = Lists(configs, names, keys, sbs, cts, assets)
        if (chosenIdx >= 0) watch(lists!!, chosenIdx)
    }

    private class Lists(val configs: List<String>, val names: List<String>, val keys: List<String>, val sbs: List<String>, val cts: List<String>, val assets: File)

    private fun nameOf(l: Lists, i: Int) = l.names.getOrNull(i) ?: "сервер ${i + 1}"

    /** Пробует способы по кругу, начиная со следующего за current (текущий — последним). Возвращает номер рабочего, -1 — никто, -2 — остановлено. */
    private fun switchFrom(l: Lists, current: Int, gen: Int, tag: String): Int {
        val order = (1..l.configs.size).map { (current + it) % l.configs.size }
        for (i in order) {
            if (gen != generation) return -2
            xray?.destroy(); xray = null
            singbox?.destroy(); singbox = null
            ct?.destroy(); ct = null
            Diag.log("$tag: пробуем «${nameOf(l, i)}»")
            val ok = runCatching { tryServer(l.configs[i], l.assets, sbConfig = l.sbs.getOrElse(i) { "" }, ctSpec = l.cts.getOrElse(i) { "" }) }.getOrDefault(false)
            l.keys.getOrNull(i)?.let { NetProbe.report(this, it, ok, 0) }
            if (ok) return i
        }
        return -1
    }

    /**
     * Сторож связи: если через текущий сервер трафик перестал ходить (оператор начал резать), сам
     * переключается на следующий способ. Туннель hev смотрит на тот же локальный порт.
     */
    private fun watch(l: Lists, start: Int) {
        val gen = ++generation
        currentIdx = start
        Thread {
            var fails = 0
            while (gen == generation && state.value == VpnState.ON) {
                runCatching { Thread.sleep(20_000) }
                if (gen != generation || state.value != VpnState.ON) return@Thread
                if (probe()) { fails = 0; continue }
                if (++fails < 2) continue
                fails = 0
                Diag.log("сторож: связь пропала, ищем рабочий способ")
                message.value = "Связь пропала, переключаемся…"
                val found = switchFrom(l, currentIdx, gen, "сторож")
                if (found == -2) return@Thread
                if (found >= 0) {
                    currentIdx = found
                    message.value = "Подключено: ${nameOf(l, found)}"
                    updateNotification("Защита включена · ${nameOf(l, found)}")
                } else {
                    message.value = "Нет связи, продолжаем пытаться…"
                }
            }
        }.start()
    }

    /** Кнопка «Сменить сервер» в уведомлении: переходим на следующий способ, сторож на это время останавливается. */
    private fun manualSwitch() {
        val l = lists ?: return
        if (state.value != VpnState.ON || switching) return
        switching = true
        Thread {
            try {
                val gen = ++generation
                message.value = "Меняем сервер…"
                updateNotification("Меняем сервер…")
                val found = switchFrom(l, currentIdx, gen, "ручная смена")
                if (found == -2) return@Thread
                if (found >= 0) {
                    message.value = "Подключено: ${nameOf(l, found)}"
                    updateNotification("Защита включена · ${nameOf(l, found)}")
                    watch(l, found)
                } else {
                    message.value = "Нет связи, продолжаем пытаться…"
                    watch(l, currentIdx)
                }
            } finally {
                switching = false
            }
        }.start()
    }

    /** Запускает ядро с этим конфигом и проверяет, ходит ли трафик через сервер. */
    private fun tryServer(config: String, assets: File, verify: Boolean = true, sbConfig: String = "", ctSpec: String = ""): Boolean {
        if (ctSpec.isNotBlank() && !startCt(ctSpec)) return false
        if (sbConfig.isNotBlank() && !startSingBox(sbConfig)) return false
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
        waitForSocks(proc)
        if (!proc.isAlive) return false
        return if (verify) probe() else true
    }

    /** Coral Transport: локальный ct-client принимает Shadowsocks от sing-box и отправляет его на сервер в нашей форме. */
    private fun startCt(spec: String): Boolean {
        val (host0, ports, key) = spec.split("|").let { Triple(it.getOrElse(0) { "" }, it.getOrElse(1) { "" }, it.getOrElse(2) { "" }) }
        val bin = File(applicationInfo.nativeLibraryDir, "libct.so")
        if (!bin.exists()) { Diag.log("ct в сборке нет"); return false }
        // Несколько серверов (мосты) через запятую: имена переводим в IP здесь, у Go-клиента на Android нет системного DNS
        val host = host0.split(",").filter { it.isNotBlank() }.mapNotNull { h ->
            if (h.any { it.isLetter() }) runCatching { InetAddress.getAllByName(h).filterIsInstance<Inet4Address>().firstOrNull()?.hostAddress }.getOrNull() else h
        }.joinToString(",")
        if (host.isEmpty()) { Diag.log("ct: не удалось определить IP $host0"); return false }
        val pb = ProcessBuilder(bin.path, "client", "-listen", "127.0.0.1:${SingBoxConfig.CT_PORT}", "-remote", host, "-ports", ports.ifBlank { "9500:9500" })
        pb.environment()["CT_KEY"] = key
        val proc = pb.redirectErrorStream(true).start()
        ct = proc
        Thread { runCatching { proc.inputStream.bufferedReader().forEachLine { Diag.log("ct: ${it.take(300)}") } } }.start()
        repeat(30) {
            if (!proc.isAlive) return false
            if (runCatching { java.net.Socket("127.0.0.1", SingBoxConfig.CT_PORT).use { true } }.getOrDefault(false)) return true
            Thread.sleep(100)
        }
        return proc.isAlive
    }

    /** Hysteria2 и Shadow-TLS: запускаем sing-box, он открывает локальный SOCKS, к которому подключается Xray. */
    private fun startSingBox(config: String): Boolean {
        val cfg = File(filesDir, "singbox.json").apply { writeText(config) }
        val bin = File(applicationInfo.nativeLibraryDir, "libsingbox.so")
        if (!bin.exists()) { Diag.log("sing-box в сборке нет"); return false }
        val proc = ProcessBuilder(bin.path, "run", "-c", cfg.path, "-D", filesDir.path).redirectErrorStream(true).start()
        singbox = proc
        Thread {
            runCatching { proc.inputStream.bufferedReader().forEachLine { Diag.log("sing-box: ${it.take(300)}") } }
        }.start()
        repeat(40) {
            if (!proc.isAlive) return false
            if (runCatching { java.net.Socket("127.0.0.1", SingBoxConfig.SOCKS_PORT).use { true } }.getOrDefault(false)) return true
            Thread.sleep(100)
        }
        return proc.isAlive
    }

    /** Ждём, пока ядро откроет локальный SOCKS-порт (обычно доли секунды), максимум 3 секунды. */
    private fun waitForSocks(proc: Process) {
        repeat(30) {
            if (!proc.isAlive) return
            val up = runCatching { java.net.Socket("127.0.0.1", XrayConfig.SOCKS_PORT).use { true } }.getOrDefault(false)
            if (up) return
            Thread.sleep(100)
        }
    }

    /** Запрос через локальный SOCKS ядра: 204 значит, сервер работает. Только HTTPS — открытый HTTP Android запрещает. */
    private fun probe(): Boolean {
        val proxy = java.net.Proxy(java.net.Proxy.Type.SOCKS, java.net.InetSocketAddress("127.0.0.1", XrayConfig.SOCKS_PORT))
        for (url in listOf("https://cp.cloudflare.com/generate_204", "https://www.gstatic.com/generate_204")) {
            runCatching {
                val c = java.net.URL(url).openConnection(proxy) as java.net.HttpURLConnection
                c.connectTimeout = 4000
                c.readTimeout = 4000
                val code = c.responseCode
                c.disconnect()
                Diag.log("проверка связи ($url): HTTP $code")
                if (code == 204) return true
            }.onFailure { Diag.log("проверка связи ($url): ${it.javaClass.simpleName}: ${it.message}") }
        }
        return false
    }

    /** У Xray на Android нет системного DNS (нет resolv.conf), поэтому подставляем IP сервера сами. */
    private fun resolveServer(config: String): String {
        val root = JSONObject(config)
        val settings = root.getJSONArray("outbounds").getJSONObject(0).getJSONObject("settings")
        if (!settings.has("vnext")) return config // Hysteria2 и Shadow-TLS: адрес сервера задан в конфиге sing-box
        val vnext = settings.getJSONArray("vnext").getJSONObject(0)
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
        generation++
        lists = null; currentIdx = -1; switching = false
        runCatching { TProxyService.TProxyStopService() }
        xray?.destroy(); xray = null
        singbox?.destroy(); singbox = null
        ct?.destroy(); ct = null
        runCatching { tun?.close() }; tun = null
        if (state.value != VpnState.ERROR) state.value = VpnState.OFF
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onRevoke() = shutdown()
    override fun onDestroy() { shutdown(); super.onDestroy() }

    /** Уведомление: по нажатию открывает приложение, кнопка «Отключить» выключает VPN прямо из шторки. */
    private fun buildNotification(text: String): Notification {
        val flags = PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        val open = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP),
            flags,
        )
        val stop = PendingIntent.getService(this, 1, Intent(this, CoralVpnService::class.java).setAction(ACTION_STOP), flags)
        val next = PendingIntent.getService(this, 2, Intent(this, CoralVpnService::class.java).setAction(ACTION_SWITCH), flags)
        return Notification.Builder(this, "vpn")
            .setContentTitle("Coral VPN").setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock).setOngoing(true).setOnlyAlertOnce(true)
            .setContentIntent(open)
            .addAction(Notification.Action.Builder(Icon.createWithResource(this, android.R.drawable.ic_menu_rotate), "Сменить сервер", next).build())
            .addAction(Notification.Action.Builder(Icon.createWithResource(this, android.R.drawable.ic_menu_close_clear_cancel), "Отключить", stop).build())
            .build()
    }

    private fun updateNotification(text: String) {
        runCatching { getSystemService(NotificationManager::class.java).notify(1, buildNotification(text)) }
    }

    private fun startForegroundCompat() {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel("vpn", "VPN", NotificationManager.IMPORTANCE_LOW))
        val n = buildNotification("Подключение…")
        if (Build.VERSION.SDK_INT >= 34) startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        else startForeground(1, n)
    }
}
