package com.coral.vpn

import android.content.Context
import android.content.Intent

/** Какие установленные приложения считать банковскими и российскими — для исключения из VPN. */
object AppRules {
    /** Банки, платёжные сервисы и госуслуги: известные имена пакетов. */
    private val BANK_PACKAGES = setOf(
        "ru.sberbankmobile", "ru.sberbank.sbbol", "ru.sberbank.sberbankid", "com.idamob.tinkoff.android",
        "ru.vtb24.mobilebanking.android", "ru.alfabank.mobile.android", "ru.raiffeisennews",
        "ru.gazprombank.android.mobilebank.app", "ru.rshb.mbank", "ru.sovcomcard.halva.v1",
        "ru.rostel", "ru.nspk.mirpay", "ru.nspk.sbpay", "ru.mts.mtsmoney", "ru.mtsbank.mobile",
    )

    /** Слова в названии приложения (строчными буквами). */
    private val BANK_WORDS = listOf(
        "сбер", "тинькофф", "т-банк", "втб", "альфа", "райффайзен", "газпромбанк", "россельхоз",
        "совкомбанк", "госуслуги", "банк", "мир пэй", "mir pay", "почта банк",
    )

    private val RU_PREFIXES = listOf(
        "ru.", "com.yandex", "com.vkontakte", "com.vk.", "com.my.", "com.idamob", "com.wildberries",
        "com.avito", "com.ozon", "com.mts", "com.beeline", "com.sberbank", "com.tinkoff",
    )

    fun isBank(pkg: String, label: String): Boolean {
        if (pkg in BANK_PACKAGES) return true
        val l = label.lowercase()
        return BANK_WORDS.any { it in l }
    }

    fun isRussian(pkg: String, label: String): Boolean =
        isBank(pkg, label) || RU_PREFIXES.any { pkg.startsWith(it) }

    fun banks(apps: List<Pair<String, String>>): Set<String> = apps.filter { isBank(it.first, it.second) }.map { it.first }.toSet()
    fun russian(apps: List<Pair<String, String>>): Set<String> = apps.filter { isRussian(it.first, it.second) }.map { it.first }.toSet()

    /** Установленные приложения с иконкой в меню: (пакет, название). */
    fun installed(ctx: Context): List<Pair<String, String>> {
        val pm = ctx.packageManager
        val i = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        return pm.queryIntentActivities(i, 0)
            .map { it.activityInfo.packageName to it.loadLabel(pm).toString() }
            .filter { it.first != ctx.packageName }
            .distinctBy { it.first }.sortedBy { it.second.lowercase() }
    }
}
