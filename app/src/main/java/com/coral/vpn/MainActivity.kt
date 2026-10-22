package com.coral.vpn

import android.app.Application
import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
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
        Button(onClick = {}, enabled = false, modifier = Modifier.fillMaxWidth()) { Text("Подключить (ядро будет в следующей версии)") }
    }
}
