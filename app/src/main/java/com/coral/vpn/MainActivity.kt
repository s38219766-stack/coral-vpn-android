package com.coral.vpn

import android.app.Application
import android.Manifest
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.ui.platform.LocalContext
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.net.URL

private val Ink = Color(0xFF0A0D18)
private val Coral = Color(0xFFFF7A59)
private val Card = Color(0x14FFFFFF)

class MainVm(app: Application) : AndroidViewModel(app) {
    private val prefs = app.getSharedPreferences("coral", Context.MODE_PRIVATE)
    var url by mutableStateOf(prefs.getString("url", "") ?: "")
    var servers by mutableStateOf<List<Server>>(emptyList())
    var status by mutableStateOf("Вставьте ссылку подписки из Coral VPN")
    var mode by mutableStateOf(RouteMode.RU_DIRECT)
    var selected by mutableStateOf<Server?>(null)
    var apps by mutableStateOf(prefs.getStringSet("apps", emptySet()) ?: emptySet())

    fun saveApps(v: Set<String>) { apps = v; prefs.edit().putStringSet("apps", v).apply() }

    fun startIntent(ctx: Context): Intent? = selected?.let {
        Intent(ctx, CoralVpnService::class.java)
            .putExtra(CoralVpnService.EXTRA_CONFIG, XrayConfig.build(it, mode))
            .putExtra(CoralVpnService.EXTRA_APPS, apps.toTypedArray())
    }

    fun load(link: String = url) {
        url = link.trim()
        prefs.edit().putString("url", url).apply()
        status = "Загрузка…"
        viewModelScope.launch(Dispatchers.IO) {
            runCatching { URL(url).readText() }
                .onSuccess {
                    val list = Subscription.parse(it)
                    servers = list
                    selected = list.firstOrNull()
                    status = if (list.isEmpty()) "В подписке нет серверов" else "Серверов: ${list.size}"
                }
                .onFailure { status = "Ошибка загрузки: ${it.message}" }
        }
    }

    fun configPreview(): String = selected?.let { XrayConfig.build(it, mode) } ?: ""
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val deepLink = intent?.data?.takeIf { it.scheme == "coral" }?.getQueryParameter("url")
        setContent {
            MaterialTheme(colorScheme = darkColorScheme(primary = Coral, background = Ink, surface = Ink)) {
                val vm: MainVm = viewModel()
                LaunchedEffect(deepLink) {
                    if (!deepLink.isNullOrBlank()) vm.load(deepLink) else if (vm.url.isNotBlank()) vm.load()
                }
                Screen(vm)
            }
        }
    }
}

@Composable
private fun Screen(vm: MainVm) {
    Column(Modifier.fillMaxSize().background(Ink).statusBarsPadding().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Coral VPN", color = Color.White, fontSize = 26.sp, fontWeight = FontWeight.ExtraBold)
        OutlinedTextField(
            value = vm.url, onValueChange = { vm.url = it }, modifier = Modifier.fillMaxWidth(),
            label = { Text("Ссылка подписки") }, singleLine = true,
        )
        Button(onClick = { vm.load() }, modifier = Modifier.fillMaxWidth()) { Text("Импортировать") }
        Text(vm.status, color = Color(0xFF9AA0B8))

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(selected = vm.mode == RouteMode.RU_DIRECT, onClick = { vm.mode = RouteMode.RU_DIRECT }, label = { Text("РФ напрямую") })
            FilterChip(selected = vm.mode == RouteMode.ALL, onClick = { vm.mode = RouteMode.ALL }, label = { Text("Всё через VPN") })
        }
        LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.weight(1f)) {
            items(vm.servers) { s ->
                Row(
                    Modifier.fillMaxWidth().background(Card, RoundedCornerShape(14.dp)).padding(14.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Column {
                        Text(s.name, color = Color.White, fontWeight = FontWeight.Bold)
                        Text("${s.security} · ${s.network} · ${s.host}:${s.port}", color = Color(0xFF9AA0B8), fontSize = 12.sp)
                    }
                    RadioButton(selected = vm.selected == s, onClick = { vm.selected = s })
                }
            }
        }
        AppsPicker(vm)
        ConnectButton(vm)
    }
}

@Composable
private fun ConnectButton(vm: MainVm) {
    val ctx = LocalContext.current
    val state by CoralVpnService.state.collectAsState()
    val msg by CoralVpnService.message.collectAsState()
    fun launch() { vm.startIntent(ctx)?.let { ctx.startForegroundService(it) } }
    val perm = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
        if (r.resultCode == android.app.Activity.RESULT_OK) launch()
    }
    val notif = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { }
    LaunchedEffect(Unit) {
        if (Build.VERSION.SDK_INT >= 33) notif.launch(Manifest.permission.POST_NOTIFICATIONS)
    }
    if (msg.isNotBlank()) Text(msg, color = Color(0xFF9AA0B8), fontSize = 12.sp, maxLines = 3)
    Button(
        onClick = {
            if (state == VpnState.ON || state == VpnState.CONNECTING) {
                ctx.startService(Intent(ctx, CoralVpnService::class.java).setAction(CoralVpnService.ACTION_STOP))
            } else {
                val ask = VpnService.prepare(ctx)
                if (ask != null) perm.launch(ask) else launch()
            }
        },
        enabled = vm.selected != null,
        modifier = Modifier.fillMaxWidth().height(56.dp),
    ) {
        Text(when (state) {
            VpnState.ON -> "Отключить"
            VpnState.CONNECTING -> "Подключение… (нажмите для отмены)"
            else -> "Подключить"
        })
    }
}

@Composable
private fun AppsPicker(vm: MainVm) {
    val ctx = LocalContext.current
    var open by remember { mutableStateOf(false) }
    val list = remember {
        val pm = ctx.packageManager
        val i = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        pm.queryIntentActivities(i, 0)
            .map { it.activityInfo.packageName to it.loadLabel(pm).toString() }
            .filter { it.first != ctx.packageName }
            .distinctBy { it.first }.sortedBy { it.second.lowercase() }
    }
    OutlinedButton(onClick = { open = true }, modifier = Modifier.fillMaxWidth()) {
        Text(if (vm.apps.isEmpty()) "Приложения: все через VPN" else "Приложения через VPN: ${vm.apps.size}")
    }
    if (open) AlertDialog(
        onDismissRequest = { open = false },
        confirmButton = { TextButton(onClick = { open = false }) { Text("Готово") } },
        dismissButton = { TextButton(onClick = { vm.saveApps(emptySet()) }) { Text("Все приложения") } },
        title = { Text("Через VPN пойдут:") },
        text = {
            LazyColumn(Modifier.heightIn(max = 420.dp)) {
                items(list) { (pkg, label) ->
                    Row(Modifier.fillMaxWidth(), verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                        Checkbox(checked = pkg in vm.apps, onCheckedChange = { on ->
                            vm.saveApps(if (on) vm.apps + pkg else vm.apps - pkg)
                        })
                        Text(label)
                    }
                }
            }
        },
    )
}
