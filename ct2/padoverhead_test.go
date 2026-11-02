package ct2

import "testing"

// Накладные расходы дополнения на потоке записей разных размеров: байт на проводе на байт данных.
func TestPaddingOverheadOnBulkWrites(t *testing.T) {
	cc, sc, _ := configs(t)
	cli, _, ce, se := pair(t, cc, sc)
	if ce != nil || se != nil {
		t.Fatal(ce, se)
	}
	for _, n := range []int{60, 200, 800, 1100, 1360, 1408, 1420, 2800, 4000, 8000, 15900} {
		r := &capture{}
		cli.rw = r
		const reps = 50
		for i := 0; i < reps; i++ {
			cli.Write(make([]byte, n))
		}
		ratio := float64(r.w.Len()) / float64(reps*n)
		t.Logf("запись %5d байт: на проводе %.2f байт на байт данных", n, ratio)
		// запись крупнее корзин (поток данных): допустимы только заголовок записи (34 байта) и добавок до 31 байта
		if n >= 1360 && ratio > 1.08 {
			t.Errorf("запись %d байт: накладные расходы %.2f (слишком много для потока данных)", n, ratio)
		}
	}
}
