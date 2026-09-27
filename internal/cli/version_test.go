package cli

import (
	"strings"
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/orchestrator"
)

// Хувилбар ХОЁР газар амьдардаг бөгөөд тэдгээр нь ӨӨР ӨӨР замаар тавигддаг:
//
//   - cli.Version          — release-д goreleaser ldflags-аар оруулна
//     (-X .../internal/cli.Version={{ .Version }})
//   - orchestrator.Version — const, ldflags ХҮРДЭГГҮЙ; гараар шинэчилнэ
//
// Тиймээс release гаргахдаа const-ыг мартвал: `tatar-kuber version` нь 1.0.3
// гэж хэлэх атлаа scan-result.json-ийн metadata.tatar_version ба SARIF-ийн
// driver.version нь 1.0.2 хэвээр үлдэнэ. Аудитын хэрэгсэл өөрийн гарал үүслийг
// худал хэлэх нь чимээгүй бөгөөд хамгийн хортой алдааны төрөл. Энэ тест яг
// тэрийг барина.
func TestVersionsAgree(t *testing.T) {
	cliVer := semverCore(Version)
	if cliVer != orchestrator.Version {
		t.Fatalf("хувилбар зөрөв: cli.Version=%q (цөм: %q) != orchestrator.Version=%q\n"+
			"release гаргахдаа ХОЁУЛАНГ нь шинэчилнэ: internal/cli/root.go ба internal/orchestrator/orchestrator.go",
			Version, cliVer, orchestrator.Version)
	}
	if strings.Count(orchestrator.Version, ".") != 2 || strings.ContainsAny(orchestrator.Version, "-+v") {
		t.Errorf("orchestrator.Version=%q нь x.y.z хэлбэртэй, угтвар/дагаваргүй байх ёстой", orchestrator.Version)
	}
}

// semverCore — "1.0.3-dev" -> "1.0.3"; "1.0.3" -> "1.0.3".
func semverCore(v string) string {
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		return v[:i]
	}
	return v
}
