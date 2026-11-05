package ct2

import "io"

// Padder решает, сколько байт дополнения добавить к кадру с dataLen байтами данных. Политика меняется без смены формата.
type Padder interface {
	Pad(dataLen int, rng io.Reader) int
}

// BucketPadder выравнивает до ближайшей «корзины» только малые записи (по длине на проводе нельзя понять размер данных).
// Крупные записи несут поток данных: большие корзины раздували бы их в разы (запись в 1411 байт превращалась в 4096), поэтому
// для них только небольшой случайный добавок. Размеры крупных записей у настоящего TLS тоже произвольные.
type BucketPadder struct{ Buckets []int }

// DefaultPadder — корзины для малых записей, до размера типичного TCP-сегмента.
var DefaultPadder Padder = BucketPadder{Buckets: []int{128, 256, 512, 1024, 1400}}

func (b BucketPadder) Pad(dataLen int, rng io.Reader) int {
	body := dataLen + frameHdr
	for _, k := range b.Buckets {
		if body <= k {
			return k - body
		}
	}
	var r [1]byte
	io.ReadFull(rng, r[:])
	return int(r[0]) % 32
}

// NoPadding отключает дополнение (для замеров накладных расходов и тестов).
type NoPadding struct{}

func (NoPadding) Pad(int, io.Reader) int { return 0 }

// Адаптивный профиль: вместо одних и тех же корзин каждый сеанс получает свой набор размеров. DPI, который накопил статистику размеров
// записей «известного» протокола, не найдёт стабильного набора (128/256/512/1024/1400 у всех сеансов и пользователей). Профиль выбирается
// независимо каждой стороной (каждая выравнивает только свои записи) и меняется с каждым сеансом.

var profileBases = [][]int{
	{128, 256, 512, 1024, 1400},
	{136, 288, 576, 1000, 1280},
	{144, 320, 640, 1100, 1360},
	{152, 384, 768, 1200, 1392},
	{128, 192, 384, 768, 1200, 1380},
}

// NewRandomPadder строит случайный профиль: выбирает основу, сдвигает каждую корзину на ±10% (кроме первой, чтобы мелкие записи
// всегда помещались) и округляет до 8 байт. Последняя корзина не больше 1400 (размер сегмента), записи крупнее получают добавок 0–31 байт.
func NewRandomPadder(rng io.Reader) Padder {
	var r [8]byte
	io.ReadFull(rng, r[:])
	base := profileBases[int(r[0])%len(profileBases)]
	out := make([]int, 0, len(base))
	prev := 0
	for i, b := range base {
		v := b
		if i > 0 {
			f := 0.9 + float64(r[1+(i%7)])/255.0*0.2 // 0,9…1,1
			v = int(float64(b)*f) / 8 * 8
		}
		if v <= prev {
			v = prev + 8
		}
		if v > 1400 {
			v = 1400 / 8 * 8
			if v <= prev {
				break
			}
		}
		out = append(out, v)
		prev = v
	}
	return BucketPadder{Buckets: out}
}
