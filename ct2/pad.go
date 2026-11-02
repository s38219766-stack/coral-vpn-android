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
