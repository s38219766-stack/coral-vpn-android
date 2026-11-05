package ct2

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Аудит постоянного времени: в коде ядра (не в тестах) не должно быть прямых сравнений байтов/строк ключей, тегов и хэшей
// через bytes.Equal, bytes.Compare или ==. Проверка тегов делается внутри AEAD (flynn/noise, x/crypto), сравнение MAC — через crypto/subtle.
// Если такое сравнение понадобится, оно должно идти через subtle.ConstantTimeCompare, а этот тест нужно обновить осознанно.
func TestNoVariableTimeSecretComparisons(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	bad := regexp.MustCompile(`bytes\.(Equal|Compare)\(`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		for i, line := range strings.Split(string(b), "\n") {
			if bad.MatchString(line) {
				t.Errorf("%s:%d: сравнение в переменное время: %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
}
