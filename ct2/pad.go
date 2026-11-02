package ct2

import "io"

// Padder решает, сколько байт дополнения добавить к кадру с dataLen байтами данных. Политика меняется без смены формата.
type Padder interface {
	Pad(dataLen int, rng io.Reader) int
}

// BucketPadder выравнивает тело кадра до ближайшей «корзины», поэтому по длине на проводе нельзя понять размер данных.
type BucketPadder struct{ Buckets []int }

// DefaultPadder — корзины, близкие к размерам обычных TLS-записей.
var DefaultPadder Padder = BucketPadder{Buckets: []int{128, 256, 512, 1024, 1400, 4096, 16000}}

func (b BucketPadder) Pad(dataLen int, rng io.Reader) int {
	body := dataLen + frameHdr
	for _, k := range b.Buckets {
		if body <= k {
			return k - body
		}
	}
	var r [1]byte
	io.ReadFull(rng, r[:])
	return int(r[0]) % 64
}

// NoPadding отключает дополнение (для замеров накладных расходов и тестов).
type NoPadding struct{}

func (NoPadding) Pad(int, io.Reader) int { return 0 }
