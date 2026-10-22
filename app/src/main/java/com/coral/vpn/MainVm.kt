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
    var apps by mutableStateOf(prefs.getStringSet("apps", emptySet()) ?: emptySet())
    var pick by mutableStateOf(prefs.getString("pick", "") ?: "") // "" = «Авто»
    var adblock by mutableStateOf(prefs.getBoolean("adblock", false))
    var login by mutableStateOf(LoginState.IDLE)
    var notice by mutableStateOf("")
    var loading by mutableStateOf(false)
    private var loginJob: Job? = null

    val loggedIn get() = subUrl.isNotBlank()

    fun setMode(m: RouteMode) { mode = m; prefs.edit().putString("mode", m.name).apply() }
    fun setAdblock(v: Boolean) { adblock = v; prefs.edit().putBoolean("adblock", v).apply() }
    fun saveApps(v: Set<String>) { apps = v; prefs.edit().putStringSet("apps", v).apply() }
    fun choose(name: String) { pick = name; prefs.edit().putString("pick", name).apply() }

    fun setSubscription(url: String) {
        subUrl = url.trim()
        prefs.edit().putString("sub", subUrl).apply()
        refresh()
    }

    fun logout() {
        subUrl = ""; servers = emptyList(); info = null; pick = ""
        prefs.edit().remove("sub").remove("pick").apply()
        login = LoginState.IDLE
    }

    fun refresh() {
        if (subUrl.isBlank()) return
        loading = true
        viewModelScope.launch(Dispatchers.IO) {
            runCatching { Api.fetchSubscription(subUrl) }
                .onSuccess { (list, ui) ->
                    servers = list; info = ui
                    notice = if (list.isEmpty()) "В подписке нет серверов — проверьте срок действия" else ""
                }
                .onFailure { notice = "Не удалось обновить подписку: ${it.message}" }
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
        return Intent(ctx, CoralVpnService::class.java)
            .putExtra(CoralVpnService.EXTRA_CONFIGS, ordered.map { XrayConfig.build(it, mode, adblock) }.toTypedArray())
            .putExtra(CoralVpnService.EXTRA_NAMES, ordered.map { it.title() }.toTypedArray())
            .putExtra(CoralVpnService.EXTRA_APPS, apps.toTypedArray())
    }
}

/** Понятное название вместо технического имени из подписки. */
fun Server.title(): String = when {
    network == "ws" -> "Защищённый"
    security == "reality" -> "Быстрый"
    else -> name
}
