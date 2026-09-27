package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/diff"
	"github.com/ochmunkh/tatar-kuber/internal/finding"
	"github.com/ochmunkh/tatar-kuber/internal/orchestrator"
)

// ── Зураглалын золиос корпус (golden corpus) ─────────────────────────────────
//
// ЭНЭ ТӨСЛИЙН ДАВТАГДСАН АЛДААНЫ АНГИЛАЛ: scanner-ийн гаралтын формат upstream-д
// өөрчлөгдөж, canonical зураглал ЧИМЭЭГҮЙ эвдэрдэг. v1.0.0-д Trivy бүтэн
// хугацаанд юу ч өгөхгүй байхад CI ногоон байсан (AVD-KSV0017 vs AVD-KSV-0017).
// v1.0.1-д Popeye-ийн 10 зураглалын 7 нь өөр утга заасан байв.
//
// Одоо үүнийг өдөр тутмын "Real cluster" guard барьдаг — гэхдээ ЗӨВХӨН upstream
// tool өөрчлөгдсөн үед, ажиллах үедээ, өдөрт нэг удаа. ӨӨРСДИЙН кодын өөрчлөлт
// зураглалыг эвдвэл (dedup, rollup, risk, severity, canonical registry) тэр
// guard хэлэхгүй — түүхий гаралт нь ижил хэвээр байх тул.
//
// Энэ тест тэр нүхийг хаана: ХӨЛДӨӨСӨН бодит scanner гаралт (examples/demo) →
// бүтэн pipeline → commit хийсэн golden үр дүнтэй тулгана. Cluster хэрэггүй,
// сүлжээ хэрэггүй, ~0.1 секунд, PR бүр дээр ажиллана.
//
// ШИНЭЧЛЭХ:  go test ./internal/cli/ -run TestGolden -update
//
// Шинэчлэхийн өмнө ЗААВАЛ тестийн гаргасан зөрүүг уншина. Зөрүү бүр нь
// "зориудаар сайжруулсан" эсвэл "санамсаргүй эвдсэн"-ийн аль нэг нь — golden-ыг
// бодолгүй шинэчлэх нь энэ хамгаалалтыг утгагүй болгоно.

var update = flag.Bool("update", false, "golden файлыг одоогийн гаралтаар дарж бичнэ")

const goldenDemo = "../../testdata/golden/demo.json"

func TestGolden_DemoCorpus(t *testing.T) {
	got := runDemoPipeline(t)
	normalizeForGolden(&got)

	gotJSON, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	if *update {
		if err := os.MkdirAll(filepath.Dir(goldenDemo), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenDemo, append(gotJSON, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("golden шинэчлэгдэв: %s (%d finding)", goldenDemo, len(got.Findings))
		return
	}

	wantJSON, err := os.ReadFile(goldenDemo)
	if err != nil {
		t.Fatalf("golden уншиж чадсангүй: %v\nҮүсгэх: go test ./internal/cli/ -run TestGolden -update", err)
	}
	if strings.TrimSpace(string(wantJSON)) == strings.TrimSpace(string(gotJSON)) {
		return
	}

	var want finding.ScanResult
	if err := json.Unmarshal(wantJSON, &want); err != nil {
		t.Fatalf("golden parse: %v", err)
	}
	t.Errorf("golden корпус зөрлөө — зураглал/оноо/dedup өөрчлөгдсөн байна:\n%s",
		explainGoldenDrift(want, got))
}

// runDemoPipeline — хөлдөөсөн raw → бүтэн pipeline. cmdScan-ыг ДУУДАХГҮЙ:
// энд шалгах зүйл нь CLI биш, канон зураглал ба оноо.
func runDemoPipeline(t *testing.T) finding.ScanResult {
	t.Helper()
	p, err := buildPipeline("../../schema/canonical-controls.yaml")
	if err != nil {
		t.Fatal(err)
	}
	raws, inv, err := loadRawDir("../../examples/demo")
	if err != nil {
		t.Fatal(err)
	}
	res, err := p.Process(raws, orchestrator.Meta{
		ClusterName: "golden-demo",
		ScanMode:    "offline",
		Lang:        "en",
		Inventory:   inv,
	})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// normalizeForGolden — ажиллах болгонд өөрчлөгддөг талбаруудыг тэглэнэ.
// Эдгээр нь зураглалын тухай ЮУ Ч хэлдэггүй тул үлдээвэл golden нь байнга
// зөрч, хүн үүнийг "дахиад л тэр" гэж бодолгүй шинэчилдэг болно — тэгвэл
// жинхэнэ зөрүү мөн л анзаарагдахгүй өнгөрнө.
//
// tatar_version-ыг ч тэглэнэ: release бүрт golden зөрөх нь утгагүй чимээ.
func normalizeForGolden(r *finding.ScanResult) {
	m := &r.Metadata
	m.ScanID, m.StartedAt, m.FinishedAt, m.TatarVersion = "", "", "", ""
	for i := range m.ScannerRuns {
		m.ScannerRuns[i].DurationMS = 0
	}
	for i := range r.Findings {
		r.Findings[i].FirstSeen, r.Findings[i].LastSeen = "", ""
	}
}

// explainGoldenDrift — 90KB JSON-ын мөр мөрийн зөрүү хэвлэхгүй. Оронд нь
// СЕМАНТИК зөрүү: аль finding гарч ирэв, аль нь алга болов, алины severity
// эсвэл control өөрчлөгдөв, scanner тус бүрийн хувь нэмэр хэрхэн хөдлөв.
// Өөрийнхөө diff хөдөлгүүрийг ашиглана — тэр яг үүний тулд бичигдсэн.
func explainGoldenDrift(want, got finding.ScanResult) string {
	var b strings.Builder
	d := diff.Compare(want, got)

	fmt.Fprintf(&b, "  finding : %d -> %d\n", d.OldTotal, d.NewTotal)
	fmt.Fprintf(&b, "  оноо    : %d -> %d\n", d.OldScore, d.NewScore)
	fmt.Fprintf(&b, "  шинэ %d · алга болсон %d · дордсон %d · сайжирсан %d\n",
		d.Counts[diff.ChangeNew], d.Counts[diff.ChangeFixed],
		d.Counts[diff.ChangeWorsened], d.Counts[diff.ChangeImproved])

	mark := map[diff.Change]string{
		diff.ChangeNew: "+ ШИНЭ    ", diff.ChangeFixed: "- АЛГА    ",
		diff.ChangeWorsened: "↑ ДОРДСОН ", diff.ChangeImproved: "↓ САЙЖИРСАН",
	}
	shown := 0
	for _, it := range d.Items {
		if it.Change == diff.ChangeUnchanged {
			continue
		}
		if shown == 0 {
			b.WriteString("\n")
		}
		if shown == 25 {
			fmt.Fprintf(&b, "  ... бусад %d зөрүү\n", len(d.Items)-shown)
			break
		}
		shown++
		sev := string(it.Severity)
		if it.OldSeverity != "" {
			sev = string(it.OldSeverity) + "->" + string(it.Severity)
		}
		fmt.Fprintf(&b, "  %s %-12s %-16s %s/%s\n",
			mark[it.Change], sev, it.CanonicalControl, it.Namespace, it.Resource)
	}

	// Scanner тус бүрийн хувь нэмэр — нэг adapter эвдэрсэн эсэхийг шууд заана.
	if len(d.Scanners) > 0 {
		b.WriteString("\n  scanner:\n")
		for _, s := range d.Scanners {
			fmt.Fprintf(&b, "    %-10s %s->%s  %d->%d\n",
				s.Scanner, s.OldStatus, s.NewStatus, s.OldFindings, s.NewFindings)
		}
	}

	// Зураглалгүй rule: шинээр нэмэгдсэн нь upstream-д шинэ код гарсан,
	// эсвэл манай зураглал алдагдсаны шинж.
	if u := unmappedDelta(want, got); u != "" {
		fmt.Fprintf(&b, "\n  зураглалгүй rule: %s\n", u)
	}

	b.WriteString("\n  Зөрүү зөв бол:  go test ./internal/cli/ -run TestGolden -update\n")
	return b.String()
}

func unmappedDelta(want, got finding.ScanResult) string {
	count := func(r finding.ScanResult) map[string]int {
		m := map[string]int{}
		for _, run := range r.Metadata.ScannerRuns {
			m[run.Scanner] = run.UnmappedCount
		}
		return m
	}
	a, c := count(want), count(got)
	var out []string
	for s, n := range c {
		if a[s] != n {
			out = append(out, fmt.Sprintf("%s %d->%d", s, a[s], n))
		}
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}
