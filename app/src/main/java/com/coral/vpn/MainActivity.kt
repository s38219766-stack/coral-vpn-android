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
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.sp
import kotlin.math.cos
import kotlin.math.sin

private val Ink = Color(0xFF0A0D18)
private val Coral = Color(0xFFFF7A59)
private val Pink = Color(0xFFE92F60)
private val Muted = Color(0xFF9FC3D6)
private val Aqua = Color(0xFF4DD0E1)
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

private class Bubble(val x: Float, val size: Float, val speed: Float, val phase: Float)

private val bubbles = List(24) { i ->
    Bubble(((i * 37) % 100) / 100f, 2f + (i * 7) % 8, 0.5f + ((i * 13) % 10) / 12f, ((i * 29) % 100) / 100f)
}

/** Подводный мир: толща воды, лучи света, пузырьки и колышущиеся кораллы. Всё рисуется кодом. */
@Composable
private fun OceanBackground() {
    val t = rememberInfiniteTransition(label = "ocean")
    val tick = t.animateFloat(0f, 1f, infiniteRepeatable(tween(16000, easing = LinearEasing)), label = "tick")
    val sway = t.animateFloat(-1f, 1f, infiniteRepeatable(tween(4600, easing = FastOutSlowInEasing), RepeatMode.Reverse), label = "sway")
    Canvas(Modifier.fillMaxSize()) {
        val w = size.width
        val h = size.height
        val sw = sway.value
        drawRect(Brush.verticalGradient(listOf(Color(0xFF0C4A6E), Color(0xFF07304F), Color(0xFF041A31), Color(0xFF020B18))))

        // лучи света сверху
        for (i in 0..4) {
            val x0 = w * (0.02f + i * 0.23f) + sw * 14f * (if (i % 2 == 0) 1 else -1)
            val ray = Path().apply {
                moveTo(x0, 0f); lineTo(x0 + w * 0.11f, 0f)
                lineTo(x0 + w * 0.34f + sw * 26f, h * 0.8f); lineTo(x0 + w * 0.10f + sw * 26f, h * 0.8f)
                close()
            }
            drawPath(ray, Brush.verticalGradient(listOf(Color(0x2E8FEFFF), Color.Transparent), startY = 0f, endY = h * 0.8f))
        }

        // пузырьки поднимаются вверх
        for (b in bubbles) {
            val p = (tick.value * b.speed + b.phase) % 1f
            val y = h * (1.06f - p * 1.16f)
            val x = w * b.x + sin(p * 12.5f + b.phase * 6f) * 10f
            val r = b.size.dp.toPx() / 1.3f
            drawCircle(Color(0x12BFEFFF), r, Offset(x, y))
            drawCircle(Color(0x44CFF4FF), r, Offset(x, y), style = Stroke(1.1.dp.toPx()))
            drawCircle(Color(0x66FFFFFF), r * 0.25f, Offset(x - r * 0.35f, y - r * 0.35f))
        }

        // дно и кораллы
        val floor = Path().apply {
            moveTo(0f, h); lineTo(0f, h * 0.945f)
            cubicTo(w * 0.25f, h * 0.925f, w * 0.5f, h * 0.96f, w * 0.75f, h * 0.935f)
            cubicTo(w * 0.88f, h * 0.925f, w * 0.95f, h * 0.94f, w, h * 0.93f)
            lineTo(w, h); close()
        }
        drawPath(floor, Brush.verticalGradient(listOf(Color(0xFF0B2238), Color(0xFF040C18)), startY = h * 0.92f, endY = h))
        val backColor = Color(0xFF2B7A9B).copy(alpha = 0.45f)
        val frontCoral = Color(0xFFFF7A59).copy(alpha = 0.9f)
        val frontPink = Color(0xFFE92F60).copy(alpha = 0.9f)
        val unit = h * 0.045f
        branch(w * 0.10f, h * 0.955f, 1.62f, unit * 1.5f, 5.dp.toPx(), 5, sw, backColor)
        branch(w * 0.52f, h * 0.965f, 1.50f, unit * 1.7f, 5.dp.toPx(), 5, sw, backColor)
        branch(w * 0.88f, h * 0.955f, 1.60f, unit * 1.5f, 5.dp.toPx(), 5, sw, backColor)
        branch(w * 0.04f, h * 0.99f, 1.45f, unit * 1.3f, 6.dp.toPx(), 5, sw, frontPink)
        branch(w * 0.30f, h * 1.0f, 1.70f, unit * 1.1f, 5.dp.toPx(), 5, sw, frontCoral)
        branch(w * 0.70f, h * 1.0f, 1.45f, unit * 1.2f, 6.dp.toPx(), 5, sw, frontCoral)
        branch(w * 0.95f, h * 0.99f, 1.70f, unit * 1.3f, 5.dp.toPx(), 5, sw, frontPink)
    }
}

/** Ветка коралла: рекурсивно раздваивается и покачивается от течения. */
private fun DrawScope.branch(x: Float, y: Float, angle: Float, len: Float, wd: Float, depth: Int, sway: Float, color: Color) {
    if (depth == 0) return
    val a = angle + sway * 0.045f * (6 - depth)
    val x2 = x + cos(a) * len
    val y2 = y - sin(a) * len
    drawLine(color, Offset(x, y), Offset(x2, y2), strokeWidth = wd, cap = StrokeCap.Round)
    branch(x2, y2, a + 0.5f, len * 0.74f, wd * 0.7f, depth - 1, sway, color)
    branch(x2, y2, a - 0.42f, len * 0.74f, wd * 0.7f, depth - 1, sway, color)
}

/** Матовое стекло: полупрозрачная заливка и светящаяся кромка. */
@Composable
private fun GlassCard(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    val shape = RoundedCornerShape(26.dp)
    Column(
        modifier.fillMaxWidth()
            .clip(shape)
            .background(Brush.linearGradient(listOf(Color(0x33FFFFFF), Color(0x0FFFFFFF))))
            .border(1.dp, Brush.linearGradient(listOf(Color(0x80FFFFFF), Color(0x14FFFFFF), Color(0x40FF9E80))), shape)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp), content = content,
    )
}

/** Жемчужина: объёмный шар с бликом; при включении светится кораллом и пускает круги. */
@Composable
private fun Pearl(size: Dp, lit: Boolean, busy: Boolean, enabled: Boolean = true, onClick: (() -> Unit)? = null, content: @Composable ColumnScope.() -> Unit) {
    val t = rememberInfiniteTransition(label = "pearl")
    val spin = t.animateFloat(0f, 360f, infiniteRepeatable(tween(1500, easing = LinearEasing)), label = "spin")
    val wave = t.animateFloat(0f, 1f, infiniteRepeatable(tween(2800, easing = LinearEasing)), label = "wave")
    val breathe = t.animateFloat(0.97f, 1.03f, infiniteRepeatable(tween(2200, easing = FastOutSlowInEasing), RepeatMode.Reverse), label = "breathe")
    val mod = Modifier.size(size).let {
        if (onClick != null) it.clickable(enabled = enabled, indication = null, interactionSource = remember { MutableInteractionSource() }, onClick = onClick) else it
    }
    Box(mod, contentAlignment = Alignment.Center) {
        Canvas(Modifier.fillMaxSize()) {
            val c = center
            val big = this.size.minDimension / 2
            val r = big * 0.64f * breathe.value
            val glow = if (lit) Color(0xFFFF7A59) else Aqua
            drawCircle(Brush.radialGradient(listOf(glow.copy(alpha = if (lit) 0.55f else 0.22f), Color.Transparent), center = c, radius = big), radius = big, center = c)
            if (lit) for (k in 0..2) {
                val p = (wave.value + k / 3f) % 1f
                drawCircle(Color(0xFFFF9E80).copy(alpha = (1f - p) * 0.4f), radius = r + (big - r) * p, center = c, style = Stroke(2.dp.toPx()))
            }
            val light = if (lit) Color(0xFFFFC2A8) else Color(0xFF5E9BC8)
            val mid = if (lit) Color(0xFFFF6B5E) else Color(0xFF204B78)
            val dark = if (lit) Color(0xFFA81C48) else Color(0xFF071A33)
            drawCircle(Brush.radialGradient(listOf(light, mid, dark), center = Offset(c.x - r * 0.38f, c.y - r * 0.42f), radius = r * 1.7f), radius = r, center = c)
            drawCircle(Brush.linearGradient(listOf(Color(0x99FFFFFF), Color(0x00FFFFFF), Color(0x40FFFFFF))), radius = r, center = c, style = Stroke(2.dp.toPx()))
            drawOval(Color.White.copy(alpha = 0.30f), topLeft = Offset(c.x - r * 0.62f, c.y - r * 0.86f), size = Size(r * 0.9f, r * 0.42f))
            drawOval(Color.White.copy(alpha = 0.10f), topLeft = Offset(c.x - r * 0.1f, c.y + r * 0.55f), size = Size(r * 0.8f, r * 0.3f))
            if (busy) rotate(spin.value, pivot = c) {
                drawArc(Brush.sweepGradient(listOf(Color(0xFFFF7A59), Color(0xFFE92F60), Color(0xFFFF7A59)), center = c), 0f, 100f, false,
                    Offset(c.x - r - 10.dp.toPx(), c.y - r - 10.dp.toPx()), Size((r + 10.dp.toPx()) * 2, (r + 10.dp.toPx()) * 2), style = Stroke(5.dp.toPx(), cap = StrokeCap.Round))
            }
        }
        Column(horizontalAlignment = Alignment.CenterHorizontally, content = content)
    }
}

/* ---------------- Вход ---------------- */

@Composable
private fun LoginScreen(vm: MainVm) {
    val ctx = LocalContext.current
    var manual by remember { mutableStateOf(false) }
    var link by remember { mutableStateOf("") }
    Box(Modifier.fillMaxSize()) {
    OceanBackground()
    Column(
        Modifier.fillMaxSize().statusBarsPadding().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center,
    ) {
        Pearl(170.dp, lit = true, busy = false) { Text("🪸", fontSize = 54.sp) }
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

    Box(Modifier.fillMaxSize()) {
    OceanBackground()
    Column(
        Modifier.fillMaxSize().statusBarsPadding().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp), horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
            Text("🪸 Coral VPN", color = Color.White, fontSize = 22.sp, fontWeight = FontWeight.ExtraBold)
            TextButton(onClick = { settings = true }) { Text("⚙ Настройки", color = Muted) }
        }

        Pearl(
            size = 270.dp, lit = state == VpnState.ON || state == VpnState.CONNECTING, busy = state == VpnState.CONNECTING,
            enabled = vm.servers.isNotEmpty(), onClick = toggle,
        ) {
            Text("⏻", fontSize = 54.sp, color = Color.White)
            Text(if (state == VpnState.ON) "Отключить" else if (state == VpnState.CONNECTING) "Отмена" else "Включить", color = Color.White, fontWeight = FontWeight.Bold)
        }

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
        Spacer(Modifier.height(90.dp))
    }
    }
    if (settings) SettingsDialog(vm) { settings = false }
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
            FilterChip(selected = vm.mode == RouteMode.RU_DIRECT, onClick = { vm.changeMode(RouteMode.RU_DIRECT) }, label = { Text("РФ напрямую") })
            FilterChip(selected = vm.mode == RouteMode.BLOCKED, onClick = { vm.changeMode(RouteMode.BLOCKED) }, label = { Text("Только заблокированное") })
            FilterChip(selected = vm.mode == RouteMode.ALL, onClick = { vm.changeMode(RouteMode.ALL) }, label = { Text("Всё") })
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
            Switch(checked = vm.adblock, onCheckedChange = { vm.changeAdblock(it) })
        }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("Мобильный режим", color = Color.White)
                Text("Для слабого мобильного интернета: меньше задержек при открытии страниц. Переподключитесь после смены.", color = Muted, fontSize = 12.sp)
            }
            Switch(checked = vm.mobile, onCheckedChange = { vm.changeMobile(it) })
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
                Text("Coral VPN 0.4", color = Muted, fontSize = 12.sp)
            }
        },
    )
}
