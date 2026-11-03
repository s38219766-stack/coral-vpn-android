package com.coral.vpn

/** Защита от утечек при обрыве VPN. Приложение само «аппаратно» заблокировать трафик не может: это делает система (Android 8+) через
 *  «Всегда включённая VPN» + «Блокировать соединения без VPN». Здесь только определяем, включено ли это, и подсказываем пользователю. */
object Leaks {
    enum class Level { OK, WARN_NO_LOCKDOWN, WARN_NOT_ALWAYS_ON, UNKNOWN }

    /** lockdown и alwaysOn — ответы системы (null — старый Android, где узнать нельзя). */
    fun level(alwaysOn: Boolean?, lockdown: Boolean?): Level = when {
        alwaysOn == null || lockdown == null -> Level.UNKNOWN
        !alwaysOn -> Level.WARN_NOT_ALWAYS_ON
        !lockdown -> Level.WARN_NO_LOCKDOWN
        else -> Level.OK
    }

    fun advice(l: Level): String? = when (l) {
        Level.WARN_NOT_ALWAYS_ON ->
            "Если VPN оборвётся, телефон выйдет в интернет напрямую и покажет ваш настоящий адрес. Включите в настройках системы «Всегда включённая VPN» для Coral и «Блокировать соединения без VPN»."
        Level.WARN_NO_LOCKDOWN ->
            "«Всегда включённая VPN» включена, но не стоит «Блокировать соединения без VPN»: при обрыве трафик может уйти напрямую. Включите этот переключатель в настройках VPN."
        else -> null
    }

    /** Строка для журнала: что именно защищено, а что нет (для разбора обращений). */
    fun describe(alwaysOn: Boolean?, lockdown: Boolean?, ipv6Routed: Boolean, dnsInTunnel: Boolean, bypassApps: Int): String =
        "защита: всегда-включённая=${alwaysOn ?: "?"}, блок-без-VPN=${lockdown ?: "?"}, IPv6 в туннеле=$ipv6Routed, DNS в туннеле=$dnsInTunnel, приложений в обход=$bypassApps"
}
