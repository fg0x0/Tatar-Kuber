package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

// E2E: examples/demo raw -> scan -> report(sarif/html) -> gate. CLI давхарга
// өмнө нь огт тестгүй байсан (flag семантик, exit code, файл бичилт).
func TestCLI_ScanReportGate_E2E(t *testing.T) {
	out := t.TempDir()
	if code := cmdScan([]string{"--raw-dir", "../../examples/demo", "--cluster", "e2e", "-o", out}); code != 0 {
		t.Fatalf("scan exit=%d", code)
	}
	resPath := filepath.Join(out, "scan-result.json")
	data, err := os.ReadFile(resPath)
	if err != nil {
		t.Fatal(err)
	}
	var res finding.ScanResult
	if err := json.Unmarshal(data, &res); err != nil {
		t.Fatal(err)
	}
	if res.Summary.TotalFindings == 0 || len(res.Metadata.ScannerRuns) != 4 {
		t.Fatalf("findings=%d runs=%d", res.Summary.TotalFindings, len(res.Metadata.ScannerRuns))
	}
	for _, r := range res.Metadata.ScannerRuns {
		if r.Status != "ingested" || r.Findings == 0 {
			t.Errorf("scanner_run %+v: ingested + findings>0 байх ёстой", r)
		}
	}

	for _, f := range []string{"sarif", "html", "json"} {
		p := filepath.Join(out, "r."+f)
		if code := cmdReport([]string{"--input", resPath, "-o", f, "--out", p}); code != 0 {
			t.Errorf("report %s exit=%d", f, code)
		}
		if fi, err := os.Stat(p); err != nil || fi.Size() == 0 {
			t.Errorf("report %s хоосон/алга", f)
		}
	}

	// Demo-д HIGH finding бий → default gate унана (exit 1); fail-on critical бол
	// CRITICAL байгаа эсэхээс хамаарна; policy файлгүй бол default high.
	if code := cmdGate([]string{"--input", resPath, "--policy", filepath.Join(out, "none.yaml")}); code != 1 {
		t.Errorf("gate default(high) exit=%d, want 1 (demo-д HIGH бий)", code)
	}
}

// Флаг ЗӨВХӨН өгсөн үед policy файлыг дарна: --min-score default (0) нь файлын
// min_score-ыг устгаж болохгүй (v1.0.0 regression).
func TestCLI_GateFlagsDoNotClobberPolicyFile(t *testing.T) {
	out := t.TempDir()
	if code := cmdScan([]string{"--raw-dir", "../../examples/demo", "-o", out}); code != 0 {
		t.Fatal("scan")
	}
	resPath := filepath.Join(out, "scan-result.json")
	pol := filepath.Join(out, ".tatar-kuber.yaml")
	// fail_on critical-аас дээш л унана; min_score 100 → score хэзээ ч 100 биш тул унах ЁСТОЙ.
	if err := os.WriteFile(pol, []byte("fail_on: critical\nmin_score: 100\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := cmdGate([]string{"--input", resPath, "--policy", pol}); code != 1 {
		t.Errorf("min_score=100 файлаас уншигдаж gate унах ёстой, exit=%d", code)
	}
	// Тодорхой --min-score 0 өгвөл файлыг дарна → зөвхөн fail_on critical үлдэнэ.
	code := cmdGate([]string{"--input", resPath, "--policy", pol, "--min-score", "0"})
	var res finding.ScanResult
	b, _ := os.ReadFile(resPath)
	_ = json.Unmarshal(b, &res)
	want := 0
	if res.Summary.Counts[finding.SeverityCritical] > 0 {
		want = 1
	}
	if code != want {
		t.Errorf("--min-score 0 explicit: exit=%d want %d", code, want)
	}
}

func TestCLI_ScanRequiresInput(t *testing.T) {
	if code := cmdScan([]string{"-o", t.TempDir()}); code != 3 {
		t.Errorf("оролтгүй scan exit=%d, want 3", code)
	}
}

// E2E: rollup-тай ба rollup-гүй хоёр бодит scan-ыг diff хийнэ. --no-rollup нь
// pod-scoped finding-үүдийг үлдээдэг тул "шинэ" гэж гарах ба rollup зөрүүг
// анхааруулах ёстой. Мөн --fail-on-new exit code-ыг шалгана.
func TestCLI_Diff_E2E(t *testing.T) {
	out := t.TempDir()
	a, b := filepath.Join(out, "a"), filepath.Join(out, "b")
	if code := cmdScan([]string{"--raw-dir", "../../examples/demo", "--cluster", "e2e", "-o", a}); code != 0 {
		t.Fatalf("scan a exit=%d", code)
	}
	if code := cmdScan([]string{"--raw-dir", "../../examples/demo", "--cluster", "e2e", "--no-rollup", "-o", b}); code != 0 {
		t.Fatalf("scan b exit=%d", code)
	}
	ap := filepath.Join(a, "scan-result.json")
	bp := filepath.Join(b, "scan-result.json")

	if code := cmdDiff([]string{"--old", ap, "--new", bp}); code != 0 {
		t.Errorf("diff exit=%d, want 0", code)
	}
	// Ижил файлыг өөртэй нь тулгавал өөрчлөлт байх ёсгүй — exit 0 хэвээр.
	if code := cmdDiff([]string{"--old", ap, "--new", ap, "--fail-on-new", "low"}); code != 0 {
		t.Errorf("identical diff exit=%d, want 0", code)
	}
	// --no-rollup-д pod-scoped MEDIUM шинээр гарна -> босго давна.
	if code := cmdDiff([]string{"--old", ap, "--new", bp, "--fail-on-new", "medium"}); code != 1 {
		t.Errorf("fail-on-new medium exit=%d, want 1", code)
	}
	// CRITICAL шинэ finding байхгүй -> дамжина.
	if code := cmdDiff([]string{"--old", ap, "--new", bp, "--fail-on-new", "critical"}); code != 0 {
		t.Errorf("fail-on-new critical exit=%d, want 0", code)
	}
	// Заавал флаг дутуу -> 3.
	if code := cmdDiff([]string{"--new", bp}); code != 3 {
		t.Errorf("missing --old exit=%d, want 3", code)
	}
	// Байхгүй файл -> 2.
	if code := cmdDiff([]string{"--old", filepath.Join(out, "nope.json"), "--new", bp}); code != 2 {
		t.Errorf("missing file exit=%d, want 2", code)
	}
}

// Хэл бол ГАРАЛТЫН шинж чанар: нэг scan-result.json-оос хоёр хэл дээрх тайлан
// гарах ёстой, scan-ыг дахин ажиллуулахгүйгээр. v1.0.2 хүртэл хэл нь scan дээр
// л сонгогддог байсан тул монгол тайлан авахын тулд бүх scan дахин ажилладаг
// байв (cluster руу дахин хандах, 4 tool дахин ажиллуулах).
func TestCLI_ReportLangSwitchesWithoutRescan(t *testing.T) {
	out := t.TempDir()
	if code := cmdScan([]string{"--raw-dir", "../../examples/demo", "--cluster", "lang", "--lang", "en", "-o", out}); code != 0 {
		t.Fatalf("scan exit=%d", code)
	}
	res := filepath.Join(out, "scan-result.json")
	before, err := os.ReadFile(res)
	if err != nil {
		t.Fatal(err)
	}

	read := func(lang string) finding.ScanResult {
		p := filepath.Join(out, "r-"+lang+".json")
		args := []string{"--input", res, "-o", "json", "--out", p}
		if lang != "" {
			args = append(args, "--lang", lang)
		}
		if code := cmdReport(args); code != 0 {
			t.Fatalf("report --lang %s exit=%d", lang, code)
		}
		var r finding.ScanResult
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatal(err)
		}
		return r
	}

	en, mn := read("en"), read("mn")
	if en.Metadata.Lang != "en" || mn.Metadata.Lang != "mn" {
		t.Fatalf("metadata.lang: en=%q mn=%q", en.Metadata.Lang, mn.Metadata.Lang)
	}
	if len(en.Findings) == 0 || len(en.Findings) != len(mn.Findings) {
		t.Fatalf("finding тоо зөрөв: %d vs %d", len(en.Findings), len(mn.Findings))
	}
	// Ядаж нэг гарчиг ҮНЭХЭЭР өөр байх ёстой — эс бөгөөс сэлгээ ажиллаагүй.
	diffs := 0
	for i := range en.Findings {
		if en.Findings[i].ID != mn.Findings[i].ID {
			t.Fatalf("finding эрэмбэ зөрөв: %s vs %s", en.Findings[i].ID, mn.Findings[i].ID)
		}
		if en.Findings[i].Title != mn.Findings[i].Title {
			diffs++
		}
	}
	if diffs == 0 {
		t.Error("en ба mn гарчиг бүгд ижил — ApplyLang ажиллаагүй")
	}

	// --lang өгөөгүй бол scan-ы хэл хэвээр (буцаад нийцтэй).
	if d := read(""); d.Metadata.Lang != "en" {
		t.Errorf("--lang-гүй: lang=%q, want en", d.Metadata.Lang)
	}

	// Хамгийн чухал: эх файл ХӨНДӨГДӨӨГҮЙ байх ёстой — эс бөгөөс result_hash
	// хүчингүй болж verify унана.
	after, err := os.ReadFile(res)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("report --lang нь scan-result.json-ыг өөрчилсөн — result_hash хүчингүй болно")
	}

	// Registry-д байхгүй хэлийг ЧИМЭЭГҮЙ en рүү унагахгүй, алдаа болгоно.
	if code := cmdReport([]string{"--input", res, "-o", "json", "--lang", "de",
		"--out", filepath.Join(out, "de.json")}); code != 3 {
		t.Errorf("--lang de exit=%d, want 3", code)
	}
}

// Офлайн ingest нь өөрийгөө "remote" гэж зарлаж байсан: cluster руу огт
// хандаагүй атлаа "амьд кластерын scan" гэсэн тайлан гаргадаг байв (v1.0.2-т
// mode нь ЗӨВХӨН -f байгаа эсэхээр шийдэгддэг, --raw-dir салаа түүнийг дамжуулдаг
// байсан). Хоёр хор: тайлан гарал үүслээ худал хэлнэ, мөн diff-ийн
// mode_mismatch хамгаалалт амьд scan ба офлайн ingest-ийг ялгаж чадахгүй болно.
func TestCLI_RawDirScanIsOffline(t *testing.T) {
	out := t.TempDir()
	if code := cmdScan([]string{"--raw-dir", "../../examples/demo", "--cluster", "mode", "-o", out}); code != 0 {
		t.Fatalf("scan exit=%d", code)
	}
	var res finding.ScanResult
	b, err := os.ReadFile(filepath.Join(out, "scan-result.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatal(err)
	}
	if res.Metadata.ScanMode != "offline" {
		t.Errorf("scan_mode=%q, want offline (--raw-dir нь scanner ажиллуулдаггүй)", res.Metadata.ScanMode)
	}
}

// gate --baseline: аль хэдийн байсан олдворт унахгүй, ЗӨВХӨН шинэ ба дордсонд
// унана. Багууд эхний өдөр 200 олдвортой танилцахдаа gate-ээ бүхэлд нь
// унтраахаас сэргийлэх зорилготой — унтраасан gate бол gate биш.
func TestCLI_GateBaseline(t *testing.T) {
	out := t.TempDir()
	if code := cmdScan([]string{"--raw-dir", "../../examples/demo", "--cluster", "bl", "-o", out}); code != 0 {
		t.Fatalf("scan exit=%d", code)
	}
	basePath := filepath.Join(out, "scan-result.json")
	none := filepath.Join(out, "none.yaml")

	// Baseline-гүй: demo-д HIGH бий тул унана.
	if code := cmdGate([]string{"--input", basePath, "--policy", none}); code != 1 {
		t.Fatalf("baseline-гүй: exit=%d, want 1", code)
	}
	// Өөрөө өөртэйгээ: өөрчлөлт алга тул давна.
	if code := cmdGate([]string{"--input", basePath, "--policy", none, "--baseline", basePath}); code != 0 {
		t.Errorf("өөрчлөлтгүй baseline: exit=%d, want 0", code)
	}

	var res finding.ScanResult
	b, err := os.ReadFile(basePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatal(err)
	}

	write := func(name string, r finding.ScanResult) string {
		p := filepath.Join(out, name)
		d, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, d, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// ШИНЭ critical нэмэхэд унана.
	withNew := res
	withNew.Findings = append(append([]finding.Finding(nil), res.Findings...), finding.Finding{
		ID: "blnew0000001", CanonicalControl: "TATAR-SEC-001", Resource: "deployment/brand-new",
		Namespace: "production", Severity: finding.SeverityCritical, Title: "new",
	})
	if code := cmdGate([]string{"--input", write("new.json", withNew), "--policy", none, "--baseline", basePath}); code != 1 {
		t.Errorf("шинэ CRITICAL: exit=%d, want 1", code)
	}

	// ДОРДСОН олдвор мөн унагана: LOW нь CRITICAL болоход "хуучин асуудал" гэж
	// чимээгүй өнгөрөх нь энэ хэрэгслийн эсэргүүцдэг зүйл.
	worse := res
	worse.Findings = append([]finding.Finding(nil), res.Findings...)
	bumped := false
	for i := range worse.Findings {
		if finding.Rank(worse.Findings[i].Severity) < finding.Rank(finding.SeverityHigh) {
			worse.Findings[i].Severity = finding.SeverityCritical
			bumped = true
			break
		}
	}
	if !bumped {
		t.Fatal("дордуулах олдвор олдсонгүй")
	}
	if code := cmdGate([]string{"--input", write("worse.json", worse), "--policy", none, "--baseline", basePath}); code != 1 {
		t.Errorf("дордсон олдвор: exit=%d, want 1", code)
	}

	// Итгэх боломжгүй baseline (өөр cluster) -> ХЭРЭГСЭХГҮЙ, бүх олдворт унана.
	other := res
	other.Metadata.ClusterName = "staging"
	if code := cmdGate([]string{"--input", basePath, "--policy", none,
		"--baseline", write("other.json", other)}); code != 1 {
		t.Errorf("cluster зөрсөн baseline: exit=%d, want 1 (baseline хэрэгсэхгүй)", code)
	}

	// Байхгүй файл -> уншилтын алдаа.
	if code := cmdGate([]string{"--input", basePath, "--policy", none,
		"--baseline", filepath.Join(out, "missing.json")}); code != 2 {
		t.Errorf("байхгүй baseline: exit=%d, want 2", code)
	}
}
