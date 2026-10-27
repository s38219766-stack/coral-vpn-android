package com.coral.vpn

import android.app.Application
import android.content.Context
import android.content.Intent
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

enum class LoginState { IDLE, WAITING, NO_SUB, FAILED }

class MainVm(app: Application) : AndroidViewModel(app) {
    private val prefs = app.getSharedPreferences("coral", Context.MODE_PRIVATE)

    var subUrl by mutableStateOf(prefs.getString("sub", "") ?: "")
    var servers by mutableStateOf<List<Server>>(emptyList())
    var info by mutableStateOf<UserInfo?>(null)
    var mode by mutableStateOf(runCatching { RouteMode.valueOf(prefs.getString("mode", "") ?: "") }.getOrDefault(RouteMode.RU_DIRECT))
    var apps by mutableStateOf(prefs.getStringSet("apps", emptySet()) ?: emptySet())   // режим «только выбранные через VPN»
    var excluded by mutableStateOf(prefs.getStringSet("excluded", emptySet()) ?: emptySet()) // режим «выбранные без VPN»
    /** all — все через VPN, exclude — все, кроме выбранных, only — только выбранные */
    var appsMode by mutableStateOf(prefs.getString("apps_mode", null) ?: if (prefs.getStringSet("apps", emptySet()).isNullOrEmpty()) "all" else "only")
    var sitesVpn by mutableStateOf(prefs.getString("sites_vpn", "") ?: "")
    var sitesDirect by mutableStateOf(prefs.getString("sites_direct", "") ?: "")
    var countries by mutableStateOf(prefs.getStringSet("countries", emptySet()) ?: emptySet())
    var banksDirect by mutableStateOf(prefs.getBoolean("banks_direct", true))
    var pick by mutableStateOf(prefs.getString("pick", "") ?: "") // "" = «Авто»
    var adblock by mutableStateOf(prefs.getBoolean("adblock", false))
    var mobile by mutableStateOf(prefs.getBoolean("mobile", false))
    var fragment by mutableStateOf(prefs.getBoolean("fragment", false))
    var eco by mutableStateOf(prefs.getBoolean("eco_battery", false))   // экономия батареи: реже проверки связи
    var login by mutableStateOf(LoginState.IDLE)
    var notice by mutableStateOf("")
    var loading by mutableStateOf(false)
    /** Название новой версии, если на сервере есть свежее приложение */
    var update by mutableStateOf<String?>(null)
    private var loginJob: Job? = null

    val loggedIn get() = subUrl.isNotBlank()

    init {
        Api.setMirrors((prefs.getString("mirrors", "") ?: "").split(",").filter { it.isNotBlank() })
        // Серверы из последней удачной загрузки: приложение работает, даже если домен сейчас недоступен
        prefs.getString("sub_cache", null)?.let { raw ->
            runCatching {
                servers = Subscription.parse(raw) + Subscription.parseExtra(prefs.getString("extra_cache", "") ?: "{}")
                info = prefs.getString("sub_info", null)?.let { Api.parseUserInfo(it) }
            }
        }
    }

    fun changeMode(m: RouteMode) { mode = m; prefs.edit().putString("mode", m.name).apply() }
    fun changeMobile(v: Boolean) { mobile = v; prefs.edit().putBoolean("mobile", v).apply() }
    fun changeEco(v: Boolean) { eco = v; prefs.edit().putBoolean("eco_battery", v).apply() }
    fun changeFragment(v: Boolean) { fragment = v; prefs.edit().putBoolean("fragment", v).apply() }
    fun changeAdblock(v: Boolean) { adblock = v; prefs.edit().putBoolean("adblock", v).apply() }
    fun changeAppsMode(m: String) { appsMode = m; prefs.edit().putString("apps_mode", m).apply() }
    fun saveExcluded(v: Set<String>) { excluded = v; prefs.edit().putStringSet("excluded", v).apply() }
    fun saveSites(vpn: String, direct: String) { sitesVpn = vpn; sitesDirect = direct; prefs.edit().putString("sites_vpn", vpn).putString("sites_direct", direct).apply() }
    fun saveCountries(v: Set<String>) { countries = v; prefs.edit().putStringSet("countries", v).apply() }
    fun changeBanks(v: Boolean) { banksDirect = v; prefs.edit().putBoolean("banks_direct", v).apply() }
    fun saveApps(v: Set<String>) { apps = v; prefs.edit().putStringSet("apps", v).apply() }
    fun choose(name: String) { pick = name; prefs.edit().putString("pick", name).apply() }

    fun setSubscription(url: String) {
        subUrl = url.trim()
        prefs.edit().putString("sub", subUrl).apply()
        refresh()
    }

    fun logout() {
        subUrl = ""; servers = emptyList(); info = null; pick = ""
        prefs.edit().remove("sub").remove("pick").remove("sub_cache").remove("sub_info").remove("extra_cache").apply()
        login = LoginState.IDLE
    }

    fun checkUpdate() {
        viewModelScope.launch(Dispatchers.IO) {
            runCatching {
                val j = Api.appInfo()
                val ctx = getApplication<Application>()
                val p = ctx.packageManager.getPackageInfo(ctx.packageName, 0)
                @Suppress("DEPRECATION")
                val mine = if (android.os.Build.VERSION.SDK_INT >= 28) p.longVersionCode else p.versionCode.toLong()
                update = if (j.optBoolean("available") && j.optLong("vc") > mine) j.optString("version", "новая") else null
            }
        }
    }

    fun refresh() {
        checkUpdate()
        if (subUrl.isBlank()) return
        loading = true
        viewModelScope.launch(Dispatchers.IO) {
            runCatching { Api.fetchRaw(subUrl) }
                .onSuccess { (body, header) ->
                    val list = Subscription.parse(body)
                    // Hysteria2 и Shadow-TLS: если сервер их не отдал, остаётся обычный список
                    val app = getApplication<Application>()
                    val extraJson = runCatching { Api.fetchExtra(subUrl, NetProbe.carrier(app), if (NetProbe.isWifi(app)) "wifi" else "mobile") }.getOrNull()
                    val extra = extraJson?.let { runCatching { Subscription.parseExtra(it) }.getOrNull() }
                        ?: Subscription.parseExtra(prefs.getString("extra_cache", "") ?: "{}")
                    if (extraJson != null && extra.isNotEmpty()) prefs.edit().putString("extra_cache", extraJson).apply()
                    servers = list + extra; info = header?.let { Api.parseUserInfo(it) }
                    notice = if (list.isEmpty()) "В подписке нет серверов — проверьте срок действия" else ""
                    if (list.isNotEmpty()) prefs.edit().putString("sub_cache", body).putString("sub_info", header).apply()
                    runCatching { Api.fetchMirrors() }.onSuccess { m ->
                        Api.setMirrors(m); prefs.edit().putString("mirrors", m.joinToString(",")).apply()
                    }
                }
                .onFailure {
                    notice = if (servers.isEmpty()) "Не удалось обновить подписку: ${it.message}"
                    else "Нет связи с сервером подписки — используем сохранённые серверы"
                }
            loading = false
        }
    }

    /** Вход через бота: открываем Telegram и ждём подтверждения. */
    fun startLogin(open: (String) -> Unit) {
        loginJob?.cancel()
        login = LoginState.WAITING
        loginJob = viewModelScope.launch(Dispatchers.IO) {
            val started = runCatching { Api.startLogin() }.getOrNull()
            if (started == null) { login = LoginState.FAILED; return@launch }
            val (token, url) = started
            withContext(Dispatchers.Main) { open(url) }
            repeat(300) { // до 10 минут
                delay(2000)
                val r = runCatching { Api.poll(token) }.getOrNull() ?: return@repeat
                when (r.optString("status")) {
                    "ok" -> { setSubscription(r.getString("subscription_url")); login = LoginState.IDLE; return@launch }
                    "no_subscription" -> { login = LoginState.NO_SUB; return@launch }
                }
            }
            login = LoginState.FAILED
        }
    }

    fun cancelLogin() { loginJob?.cancel(); login = LoginState.IDLE }

    /** Выбранный сервер идёт первым, остальные — запасные. «Авто» — в порядке подписки. */
    fun startIntent(ctx: Context): Intent? {
        if (servers.isEmpty()) return null
        val first = servers.firstOrNull { it.name == pick } ?: servers.first()
        val ordered = listOf(first) + servers.filter { it != first }
        // «Авто»: если обычные способы не подключились, в конце пробуем те же TCP-серверы с дроблением TLS-рукопожатия
        val fragVariants = if (pick.isBlank() && !fragment) ordered.filter { it.kind == "vless" } else emptyList()
        fun cfg(sv: Server, frag: Boolean) = XrayConfig.build(sv, mode, adblock, mobile, frag, XrayConfig.cleanDomains(sitesVpn), XrayConfig.cleanDomains(sitesDirect), countries.toList())
        // Банки и госуслуги по умолчанию всегда идут мимо VPN — на уровне системы, а не по адресам сайтов
        val banks = if (banksDirect) AppRules.banks(AppRules.installed(ctx)) else emptySet()
        val (appListMode, appList) = when {
            appsMode == "only" && (apps - banks).isNotEmpty() -> "only" to (apps - banks)
            appsMode == "exclude" -> "exclude" to (excluded + banks)
            else -> "exclude" to banks
        }
        return Intent(ctx, CoralVpnService::class.java)
            .putExtra(CoralVpnService.EXTRA_CONFIGS, (ordered.map { cfg(it, fragment) } + fragVariants.map { cfg(it, true) }).toTypedArray())
            .putExtra(CoralVpnService.EXTRA_NAMES, (ordered.map { it.title() } + fragVariants.map { it.title() + " + дробление" }).toTypedArray())
            .putExtra(CoralVpnService.EXTRA_KEYS, (ordered.map { it.transportKey() } + fragVariants.map { "fragment" }).toTypedArray())
            .putExtra(CoralVpnService.EXTRA_SB, (ordered.map { SingBoxConfig.build(it) ?: "" } + fragVariants.map { "" }).toTypedArray())
            .putExtra(CoralVpnService.EXTRA_CT, (ordered.map { ctSpec(it) } + fragVariants.map { "" }).toTypedArray())
            .putExtra(CoralVpnService.EXTRA_AUTO, pick.isBlank())
            .putExtra(CoralVpnService.EXTRA_APPS, appList.toTypedArray())
            .putExtra(CoralVpnService.EXTRA_APPS_MODE, appListMode)
            .putExtra(CoralVpnService.EXTRA_MOBILE, mobile)
    }
}

/** Параметры ct-client для сервера Coral Transport: «хост|диапазон портов|ключ»; для остальных пусто. */
fun ctSpec(s: Server): String = if (s.kind == "ct") "${s.host}|${s.ports}|${s.ctKey}" else ""

/** Ключ транспорта для статистики: по нему сервер знает, что работает у какого оператора. */
fun Server.transportKey(): String = when {
    kind == "hysteria2" -> "hysteria2"
    kind == "tuic" -> "tuic"
    kind == "ss2022" -> "ss2022"
    kind == "ct" -> "ct"
    kind == "shadowtls" -> "shadowtls"
    network == "ws" -> "ws"
    network == "xhttp" -> "xhttp"
    name.contains("Coral RU") -> "reality_ru"
    name.contains("Coral FI") -> "reality_fi"
    name.contains("Coral US") -> "reality_us"
    security == "reality" && port != 443 -> "reality_ip"
    else -> "reality"
}

/** Понятное название вместо технического имени из подписки. */
fun Server.title(): String = when {
    kind != "vless" -> name
    network == "ws" -> "Защищённый"
    network == "xhttp" -> "Запасной (XHTTP)"
    name.contains("Coral RU") -> "Через Россию"
    name.contains("Coral US") -> "США"
    name.contains("Coral FI2") -> "Финляндия 2"
    name.contains("Coral FI") -> "Финляндия"
    security == "reality" && port != 443 -> "Резервный (по IP)"
    security == "reality" -> "Быстрый"
    else -> name
}
