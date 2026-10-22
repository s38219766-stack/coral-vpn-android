package com.coral.vpn

/** JNI-обёртка над hev-socks5-tunnel (MIT). Имя класса и пакет задаются при сборке (-DPKGNAME=com/coral/vpn). */
object TProxyService {
    init { System.loadLibrary("hev-socks5-tunnel") }

    @JvmStatic external fun TProxyStartService(configPath: String, fd: Int)
    @JvmStatic external fun TProxyStopService()
    @JvmStatic external fun TProxyGetStats(): LongArray
}
