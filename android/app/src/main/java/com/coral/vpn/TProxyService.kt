package com.coral.vpn

/**
 * JNI-обёртка над hev-socks5-tunnel (MIT). Сигнатуры должны точно совпадать с таблицей методов
 * в hev-jni.c: иначе RegisterNatives не сработает и приложение упадёт при загрузке библиотеки.
 */
object TProxyService {
    init { System.loadLibrary("hev-socks5-tunnel") }

    @JvmStatic external fun TProxyStartService(configPath: String, fd: Int): Boolean
    @JvmStatic external fun TProxyStopService(): Boolean
    @JvmStatic external fun TProxyIsRunning(): Boolean
    @JvmStatic external fun TProxyGetStats(): LongArray
}
