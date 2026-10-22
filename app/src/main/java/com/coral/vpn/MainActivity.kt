package com.coral.vpn

import android.Manifest
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.animation.core.*
import androidx.compose.foundation.*
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

private val Ink = Color(0xFF0A0D18)
private val Coral = Color(0xFFFF7A59)
private val Pink = Color(0xFFE92F60)
private val Muted = Color(0xFF9AA0B8)
private val Glass = Color(0x14FFFFFF)
private val Good = Color(0xFF3DDC97)

class MainActivity : ComponentActivity() {
    private val vm: MainVm by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        handleDeepLink(intent)
        if (vm.loggedIn) vm.refresh()
        setContent {
            MaterialTheme(colorScheme = darkColorScheme(primary = Coral, background = Ink, surface = Ink)) {
                if (vm.loggedIn) HomeScreen(vm) else LoginScreen(vm)
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleDeepLink(intent)
    }

    /** coral://add?url=<подписка> — кнопка «Открыть в Coral» из Mini App. */
    private fun handleDeepLink(i: Intent?) {
        val link = i?.data?.takeIf { it.scheme == "coral" }?.getQueryParameter("url")
        if (!link.isNullOrBlank()) vm.setSubscription(link)
    }
}

private val bg = Brush.verticalGradient(listOf(Ink, Color(0xFF160B22)))

@Composable
private fun GlassCard(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    Column(
        modifier.fillMaxWidth().background(Glass, RoundedCornerShape(22.dp)).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp), content = content,
    )
}

/* ---------------- Вход ---------------- */

@Composable
private fun LoginScreen(vm: MainVm) {
    val ctx = LocalContext.current
    var manual by remember { mutableStateOf(false) }
    var link by remember { mutableStateOf("") }
    Column(
        Modifier.fillMaxSize().background(bg).statusBarsPadding().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center,
    ) {
        Text("🪸", fontSize = 72.sp)
        Spacer(Modifier.height(8.dp))
        Text("Coral VPN", color = Color.White, fontSize = 30.sp, fontWeight = FontWeight.ExtraBold)
        Text("Быстрый и приватный доступ", color = Muted, modifier = Modifier.padding(top = 4.dp, bottom = 32.dp))

        when (vm.login) {
            LoginState.WAITING -> {
                CircularProgressIndicator(color = Coral)
                Spacer(Modifier.height(16.dp))
                Text("Подтвердите вход в Telegram и вернитесь сюда", color = Muted, textAlign = TextAlign.Center)
                TextButton(onClick = { vm.cancelLogin() }) { Text("Отмена") }
            }
            LoginState.NO_SUB -> {
                Text("У вас пока нет подписки", color = Color.White, fontWeight = FontWeight.Bold)
                Text("Откройте бота, нажмите «Попробовать бесплатно» или введите промокод — затем войдите снова.",
                    color = Muted, textAlign = TextAlign.Center, modifier = Modifier.padding(vertical = 12.dp))
                Button(onClick = { ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(Api.BOT))) }, modifier = Modifier.fillMaxWidth().height(52.dp)) { Text("Открыть бота") }
                TextButton(onClick = { vm.cancelLogin() }) { Text("Назад") }
            }
            else -> {
                if (vm.login == LoginState.FAILED) Text("Не удалось войти. Проверьте интернет и попробуйте ещё раз.", color = Color(0xFFFF5D6C), modifier = Modifier.padding(bottom = 12.dp), textAlign = TextAlign.Center)
                Button(
                    onClick = { vm.startLogin { url -> ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) } },
                    modifier = Modifier.fillMaxWidth().height(56.dp),
                ) { Text("Войти через Telegram", fontSize = 16.sp, fontWeight = FontWeight.Bold) }
                TextButton(onClick = { manual = true }) { Text("У меня есть ссылка подписки", color = Muted) }
            }
        }
    }
    if (manual) AlertDialog(
        onDismissRequest = { manual = false },
        title = { Text("Ссылка подписки") },
        text = { OutlinedTextField(value = link, onValueChange = { link = it }, singleLine = true, placeholder = { Text("https://…/sub/…") }) },
        confirmButton = { TextButton(onClick = { vm.setSubscription(link); manual = false }) { Text("Добавить") } },
        dismissButton = { TextButton(onClick = { manual = false }) { Text("Отмена") } },
    )
}

/* ---------------- Главный экран ---------------- */

@Composable
private fun HomeScreen(vm: MainVm) {
    val ctx = LocalContext.current
    val state by CoralVpnService.state.collectAsState()
    val msg by CoralVpnService.message.collectAsState()
    var settings by remember { mutableStateOf(false) }

    fun launch() { vm.startIntent(ctx)?.let { ctx.startForegroundService(it) } }
    val perm = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
        if (r.resultCode == android.app.Activity.RESULT_OK) launch()
    }
    val notif = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { }
    LaunchedEffect(Unit) { if (Build.VERSION.SDK_INT >= 33) notif.launch(Manifest.permission.POST_NOTIFICATIONS) }

    val toggle: () -> Unit = {
        if (state == VpnState.ON || state == VpnState.CONNECTING) {
            ctx.startService(Intent(ctx, CoralVpnService::class.java).setAction(CoralVpnService.ACTION_STOP))
        } else {
            val ask = VpnService.prepare(ctx)
            if (ask != null) perm.launch(ask) else launch()
        }
    }

    Column(
        Modifier.fillMaxSize().background(bg).statusBarsPadding().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp), horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
            Text("🪸 Coral VPN", color = Color.White, fontSize = 22.sp, fontWeight = FontWeight.ExtraBold)
            TextButton(onClick = { settings = true }) { Text("⚙ Настройки", color = Muted) }
        }

        PowerButton(state, enabled = vm.servers.isNotEmpty(), onClick = toggle)

        Text(
            when (state) {
                VpnState.ON -> "Защита включена"
                VpnState.CONNECTING -> "Подключение…"
                VpnState.ERROR -> "Не удалось подключиться"
                else -> "Не защищено"
            },
            color = if (state == VpnState.ON) Good else Color.White, fontSize = 20.sp, fontWeight = FontWeight.Bold,
        )
        Text(
            when {
                state == VpnState.ON || state == VpnState.CONNECTING -> msg
                vm.servers.isEmpty() && vm.loading -> "Загрузка подписки…"
                vm.servers.isEmpty() -> vm.notice.ifBlank { "Нет серверов" }
                else -> "Нажмите кнопку, чтобы подключиться"
            },
            color = Muted, fontSize = 13.sp, textAlign = TextAlign.Center, maxLines = 2,
        )
        if (state == VpnState.ERROR) Text(msg, color = Color(0xFFFF5D6C), fontSize = 12.sp, textAlign = TextAlign.Center, maxLines = 3)

        AccountCard(vm.info)
        ServerCard(vm)
        RouteCard(vm)
        Spacer(Modifier.height(24.dp))
    }
    if (settings) SettingsDialog(vm) { settings = false }
}

@Composable
private fun PowerButton(state: VpnState, enabled: Boolean, onClick: () -> Unit) {
    val t = rememberInfiniteTransition(label = "power")
    val spin by t.animateFloat(0f, 360f, infiniteRepeatable(tween(1400, easing = LinearEasing)), label = "spin")
    val pulse by t.animateFloat(0.9f, 1.05f, infiniteRepeatable(tween(1800), RepeatMode.Reverse), label = "pulse")
    val on = state == VpnState.ON
    val busy = state == VpnState.CONNECTING
    Box(
        Modifier.size(250.dp).clickable(
            enabled = enabled, indication = null, interactionSource = remember { MutableInteractionSource() }, onClick = onClick,
        ),
        contentAlignment = Alignment.Center,
    ) {
        Canvas(Modifier.fillMaxSize()) {
            val stroke = 10.dp.toPx()
            val r = size.minDimension / 2 - stroke
            if (on) drawCircle(Brush.radialGradient(listOf(Coral.copy(alpha = 0.38f), Color.Transparent)), radius = size.minDimension / 2 * pulse)
            drawCircle(Color(0x22FFFFFF), radius = r, style = Stroke(stroke))
            val sweep = Brush.sweepGradient(listOf(Coral, Pink, Coral))
            if (busy) {
                rotate(spin) {
                    drawArc(sweep, 0f, 110f, false, Offset(stroke, stroke), Size(size.width - 2 * stroke, size.height - 2 * stroke), style = Stroke(stroke, cap = StrokeCap.Round))
                }
            } else if (on) {
                drawCircle(sweep, radius = r, style = Stroke(stroke))
            }
        }
        Box(
            Modifier.size(180.dp).clip(CircleShape).background(
                if (on || busy) Brush.linearGradient(listOf(Coral, Pink))
                else Brush.linearGradient(listOf(Color(0xFF262B47), Color(0xFF181C32)))
            ),
            contentAlignment = Alignment.Center,
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text("⏻", fontSize = 52.sp, color = Color.White)
                Text(if (on) "Отключить" else if (busy) "Отмена" else "Включить", color = Color.White, fontWeight = FontWeight.Bold)
            }
        }
    }
}

@Composable
private fun AccountCard(info: UserInfo?) {
    GlassCard {
        Text("Подписка", color = Color.White, fontWeight = FontWeight.Bold)
        if (info == null || info.expire == 0L) {
            Text("Сведения загружаются…", color = Muted, fontSize = 13.sp)
        } else {
            val days = ((info.expire * 1000 - System.currentTimeMillis()) / 86_400_000L).coerceAtLeast(0)
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(if (days > 0) "Осталось $days дн." else "Срок истёк", color = if (days > 0) Good else Color(0xFFFF5D6C), fontWeight = FontWeight.SemiBold)
                Text("%.1f ГБ".format(info.used / 1_073_741_824.0), color = Muted)
            }
            LinearProgressIndicator(progress = { (days / 30f).coerceIn(0.03f, 1f) }, modifier = Modifier.fillMaxWidth().height(6.dp).clip(RoundedCornerShape(6.dp)), color = Coral, trackColor = Color(0x22FFFFFF))
        }
    }
}

@Composable
private fun ServerCard(vm: MainVm) {
    GlassCard {
        Text("Сервер", color = Color.White, fontWeight = FontWeight.Bold)
        Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(selected = vm.pick.isEmpty(), onClick = { vm.choose("") }, label = { Text("Авто") })
            vm.servers.forEach { s ->
                FilterChip(selected = vm.pick == s.name, onClick = { vm.choose(s.name) }, label = { Text(s.title()) })
            }
        }
        Text("«Авто» выберет рабочий сервер сам и переключится, если один перестанет отвечать.", color = Muted, fontSize = 12.sp)
    }
}

@Composable
private fun RouteCard(vm: MainVm) {
    GlassCard {
        Text("Маршрутизация", color = Color.White, fontWeight = FontWeight.Bold)
        Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(selected = vm.mode == RouteMode.RU_DIRECT, onClick = { vm.setMode(RouteMode.RU_DIRECT) }, label = { Text("РФ напрямую") })
            FilterChip(selected = vm.mode == RouteMode.BLOCKED, onClick = { vm.setMode(RouteMode.BLOCKED) }, label = { Text("Только заблокированное") })
            FilterChip(selected = vm.mode == RouteMode.ALL, onClick = { vm.setMode(RouteMode.ALL) }, label = { Text("Всё") })
        }
        Text(
            when (vm.mode) {
                RouteMode.RU_DIRECT -> "Российские сайты и банки работают напрямую, остальное — через VPN."
                RouteMode.BLOCKED -> "Через VPN идут Instagram, YouTube, Discord, ChatGPT и другие заблокированные сервисы. Всё остальное — напрямую."
                RouteMode.ALL -> "Весь трафик идёт через VPN."
            }, color = Muted, fontSize = 12.sp,
        )
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("Блокировать рекламу", color = Color.White)
                Text("Реклама и трекеры режутся до загрузки", color = Muted, fontSize = 12.sp)
            }
            Switch(checked = vm.adblock, onCheckedChange = { vm.setAdblock(it) })
        }
        AppsPicker(vm)
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
        Text(if (vm.apps.isEmpty()) "Приложения: все через VPN" else "Через VPN только: ${vm.apps.size} прил.")
    }
    if (open) AlertDialog(
        onDismissRequest = { open = false },
        confirmButton = { TextButton(onClick = { open = false }) { Text("Готово") } },
        dismissButton = { TextButton(onClick = { vm.saveApps(emptySet()) }) { Text("Все приложения") } },
        title = { Text("Через VPN пойдут:") },
        text = {
            LazyColumn(Modifier.heightIn(max = 420.dp)) {
                items(list) { (pkg, label) ->
                    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = pkg in vm.apps, onCheckedChange = { on -> vm.saveApps(if (on) vm.apps + pkg else vm.apps - pkg) })
                        Text(label)
                    }
                }
            }
        },
    )
}

@Composable
private fun SettingsDialog(vm: MainVm, onClose: () -> Unit) {
    val ctx = LocalContext.current
    AlertDialog(
        onDismissRequest = onClose,
        confirmButton = { TextButton(onClick = onClose) { Text("Закрыть") } },
        title = { Text("Настройки") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                TextButton(onClick = { vm.refresh(); onClose() }) { Text("Обновить подписку") }
                TextButton(onClick = { ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(Api.BOT))) }) { Text("Открыть бота (оплата, друзья, бонусы)") }
                TextButton(onClick = { Diag.share(ctx) }) { Text("Отправить журнал разработчику") }
                TextButton(onClick = { vm.logout(); onClose() }) { Text("Выйти из аккаунта", color = Color(0xFFFF5D6C)) }
                Text("Coral VPN 0.3", color = Muted, fontSize = 12.sp)
            }
        },
    )
}
