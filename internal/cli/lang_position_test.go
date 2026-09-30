package cli

import (
	"os"
	"reflect"
	"testing"
)

// Глобал `--lang` нь КОМАНДЫН ӨМНӨ бичигдэж болно. setLang нь утгыг уншдаг ч
// аргументаас ХАСдаггүй байсан тул os.Args[1] нь "--lang" хэвээр үлдэж,
// Execute-ийн switch түүнийг команд гэж үзэн exit 3 буцаадаг байв —
// `--lang en|mn` гэж тусламжийн бичвэрт ерөнхий флаг гэж бичсэн хэрнээ.
func TestStripLeadingLang(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"хос хэлбэр", []string{"--lang", "mn", "--help"}, []string{"--help"}},
		{"тэнцүү хэлбэр", []string{"--lang=mn", "--help"}, []string{"--help"}},
		{"нэг зураас", []string{"-lang", "mn", "version"}, []string{"version"}},
		{"нэг зураас тэнцүү", []string{"-lang=mn", "version"}, []string{"version"}},
		{"утгагүй", []string{"--lang"}, []string{}},
		{"давхар", []string{"--lang", "mn", "--lang=en", "doctor"}, []string{"doctor"}},
		{"флаггүй", []string{"report", "--lang", "mn"}, []string{"report", "--lang", "mn"}},
		{"командын дараах нь хөндөгдөхгүй", []string{"scan", "--lang=mn"}, []string{"scan", "--lang=mn"}},
		{"хоосон", []string{}, []string{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := stripLeadingLang(c.in)
			if len(got) == 0 && len(c.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("stripLeadingLang(%q) = %q, хүлээсэн %q", c.in, got, c.want)
			}
		})
	}
}

// Execute нь команд сонгохоосоо өмнө глобал --lang-ийг хасаж байгаа эсэх.
// `version` нь гаднын файл шаарддаггүй цорын ганц команд тул үүгээр шалгав.
func TestExecuteAcceptsGlobalLangBeforeCommand(t *testing.T) {
	orig := os.Args
	defer func() { os.Args = orig; setLang(nil) }()

	for _, args := range [][]string{
		{"tatar-kuber", "--lang", "mn", "version"},
		{"tatar-kuber", "--lang=mn", "version"},
		{"tatar-kuber", "-lang", "en", "version"},
		{"tatar-kuber", "version"},
	} {
		os.Args = args
		if code := Execute(); code != 0 {
			t.Errorf("Execute(%q) = %d, хүлээсэн 0", args, code)
		}
	}

	// Танигдаагүй хэл нь хаана бичигдсэнээс үл хамааран хэрэглээний алдаа (3).
	os.Args = []string{"tatar-kuber", "--lang", "de", "version"}
	if code := Execute(); code != 3 {
		t.Errorf("Execute(--lang de version) = %d, хүлээсэн 3", code)
	}
}
