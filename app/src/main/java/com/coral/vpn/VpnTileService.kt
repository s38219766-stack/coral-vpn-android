package com.coral.vpn

import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

/** Плитка быстрых настроек: включает и выключает VPN прямо из шторки, не открывая приложение. */
class VpnTileService : TileService() {
    private var job: Job? = null

    override fun onStartListening() {
        job = CoroutineScope(Dispatchers.Main).launch { CoralVpnService.state.collect { render(it) } }
    }

    override fun onStopListening() {
        job?.cancel(); job = null
    }

    private fun render(s: VpnState) {
        val tile = qsTile ?: return
        tile.state = if (s == VpnState.ON || s == VpnState.CONNECTING) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = "Coral VPN"
        if (Build.VERSION.SDK_INT >= 29) {
            tile.subtitle = when (s) { VpnState.ON -> "Включено"; VpnState.CONNECTING -> "Подключение…"; else -> "Выключено" }
        }
        tile.updateTile()
    }

    override fun onClick() {
        val s = CoralVpnService.state.value
        if (s == VpnState.ON || s == VpnState.CONNECTING) {
            startService(Intent(this, CoralVpnService::class.java).setAction(CoralVpnService.ACTION_STOP))
            return
        }
        // Разрешение на VPN ещё не выдано, или серверов нет: открываем приложение, там всё объяснят
        val start = if (VpnService.prepare(this) == null) MainVm(application).startIntent(this) else null
        if (start != null) startForegroundService(start) else openApp()
    }

    @Suppress("DEPRECATION")
    private fun openApp() {
        val intent = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= 34) {
            startActivityAndCollapse(PendingIntent.getActivity(this, 3, intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT))
        } else {
            startActivityAndCollapse(intent)
        }
    }
}
