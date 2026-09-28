package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ochmunkh/tatar-kuber/internal/diff"
	"github.com/ochmunkh/tatar-kuber/internal/finding"
	"github.com/ochmunkh/tatar-kuber/internal/policy"
)

// cmdGate — CI/CD gatekeeper: scan-result.json-ыг .tatar-kuber.yaml бодлоготой
// тулгаж, severity босго / cluster score-оор pass/fail шийдэж exit code буцаана.
//
//	exit 0 — PASSED, exit 1 — FAILED, exit 2/3 — алдаа.
func cmdGate(args []string) int {
	fs := flag.NewFlagSet("gate", flag.ExitOnError)
	input := fs.String("input", "scan-result.json", "scan-result.json зам")
	policyPath := fs.String("policy", ".tatar-kuber.yaml", "бодлогын файл")
	failOn := fs.String("fail-on", "", "severity босго (файлыг дарна): critical|high|medium|low")
	minScore := fs.Int("min-score", 0, "cluster score доод хязгаар (файлыг дарна; 0 = хэрэгсэхгүй)")
	baseline := fs.String("baseline", "", "өмнөх scan-result.json — зөвхөн ШИНЭ ба ДОРДСОН олдворт унана")
	_ = fs.Parse(args)
	// Флагийг ЗӨВХӨН хэрэглэгч тодорхой өгсөн үед policy файлыг дарна. Өмнө нь
	// default утга (--min-score 0, action.yml-ийн --fail-on high) файлын утгыг
	// үргэлж дарж, .tatar-kuber.yaml утгагүй болж байсан.
	setFlags := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { setFlags[f.Name] = true })

	data, err := os.ReadFile(*input)
	if err != nil {
		fmt.Fprintln(os.Stderr, "алдаа:", err)
		return 2
	}
	var res finding.ScanResult
	if err := json.Unmarshal(data, &res); err != nil {
		fmt.Fprintln(os.Stderr, "алдаа: scan-result.json parse:", err)
		return 2
	}

	pol, err := policy.Load(*policyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "алдаа:", err)
		return 2
	}
	if setFlags["fail-on"] && *failOn != "" {
		pol.FailOn = *failOn
	}
	if setFlags["min-score"] {
		pol.MinScore = *minScore
	}
	if !pol.ValidFailOn() {
		fmt.Fprintf(os.Stderr, "анхаар: fail_on='%s' танигдсангүй (critical|high|medium|low) — 'high' гэж үзнэ\n", pol.FailOn)
	}

	r := pol.Evaluate(res, time.Now())

	// --baseline: аль хэдийн байсан асуудлыг унагахгүй, ЗӨВХӨН шинэ ба дордсоныг
	// босгонд тооцно. Багууд эхний өдөр 200 олдвортой танилцахдаа gate-ээ
	// унтраахаас сэргийлэх зорилготой — унтраасан gate бол gate биш.
	baselineNote := ""
	if *baseline != "" {
		note, code := applyBaseline(&r, pol, res, *baseline)
		if code != 0 {
			return code
		}
		baselineNote = note
	}

	// Suppression-ууд хүчинтэй canonical control руу заасан эсэхийг registry-тэй тулгана.
	if regPath, err := resolveRegistry(""); err == nil {
		if reg, err := loadRegistry(regPath); err == nil {
			known := map[string]bool{}
			for _, c := range reg.Controls {
				known[c.ID] = true
			}
			r.UnknownRules = pol.UnknownControls(known)
		}
	}

	fmt.Printf("TATAR-Kuber gate — fail_on=%s  score=%d", r.FailOn, r.Score)
	if r.MinScore > 0 {
		fmt.Printf("  min_score=%d", r.MinScore)
	}
	fmt.Printf("  (suppressed=%d)", len(r.Suppressed))
	if baselineNote != "" {
		fmt.Printf("  %s", baselineNote)
	}
	fmt.Printf("\n\n")

	for _, s := range r.InvalidRules {
		fmt.Fprintf(os.Stderr, "анхаар: suppression '%s' expires формат буруу (%s) — YYYY-MM-DD байх ёстой\n", s.Control, s.Expires)
	}
	for _, s := range r.ExpiredRules {
		fmt.Fprintf(os.Stderr, "анхаар: suppression '%s' хугацаа дууссан (%s) — дахин идэвхжсэнгүй\n", s.Control, s.Expires)
	}
	for _, s := range r.UnknownRules {
		fmt.Fprintf(os.Stderr, "анхаар: suppression '%s' canonical registry-д БАЙХГҮЙ control руу заасан — бичиглэлийн алдаа байж магадгүй\n", s.Control)
	}
	// Танигдахгүй control-ууд дээр "тохироогүй" гэж давхар анхааруулахгүй —
	// шалтгаан аль хэдийн хэлэгдсэн.
	unknown := map[string]bool{}
	for _, s := range r.UnknownRules {
		unknown[s.Control] = true
	}
	for _, s := range r.UnusedRules {
		if unknown[s.Control] {
			continue
		}
		scope := s.Control
		if s.Resource != "" {
			scope += " " + s.Resource
		}
		fmt.Fprintf(os.Stderr, "анхаар: suppression '%s' ямар ч олдворт тохироогүй — асуудал зассан эсвэл resource дахин нэрлэгдсэн байж магадгүй (хуучирсан дүрмийг устгана уу)\n", scope)
	}

	if len(r.Violations) > 0 {
		fmt.Printf("Босго давсан %d олдвор:\n", len(r.Violations))
		for _, f := range r.Violations {
			ns := ""
			if f.Namespace != "" {
				ns = f.Namespace + "/"
			}
			fmt.Printf("  [%s] %s  %s%s  (%s)\n", f.Severity, f.CanonicalControl, ns, f.Resource, f.Title)
		}
		fmt.Println()
	}

	if r.Passed {
		fmt.Println("✓ GATE PASSED")
		return 0
	}
	fmt.Println("✗ GATE FAILED —", joinReasons(r.Reasons))
	return 1
}

func joinReasons(rs []string) string {
	out := ""
	for i, r := range rs {
		if i > 0 {
			out += "; "
		}
		out += r
	}
	return out
}

// ── baseline ────────────────────────────────────────────────────────────────

// baselineUntrusted — эдгээр анхааруулга гарвал "шинэ" гэсэн олонлог утгагүй
// болно: өөр cluster, өөр горим, нэг тал нь --no-rollup (resource өөрчлөгдөж
// ID бүр зөрнө), эсвэл схем зөрсөн. Ийм үед baseline-ыг ХЭРЭГСЭХГҮЙ — аюулгүй
// байдлын gate эргэлзээтэй үедээ ХААЛТТАЙ талдаа унах ёстой.
var baselineUntrusted = map[string]bool{
	"cluster_mismatch": true, "mode_mismatch": true,
	"rollup_mismatch": true, "schema_mismatch": true,
}

// applyBaseline — r.Violations-аас baseline-д аль хэдийн байсан олдворуудыг
// хасна. Дордсон (severity өссөн) олдвор ҮЛДЭНЭ: LOW нь CRITICAL болоход
// "хуучин асуудал" гэж чимээгүй өнгөрөх нь яг энэ хэрэгслийн эсэргүүцдэг зүйл.
//
// Suppression-ий бүртгэлийг (хугацаа дууссан / тохироогүй дүрэм) БҮТЭН олдворын
// жагсаалт дээр тооцсон хэвээр үлдээнэ — эс бөгөөс baseline-д байсан finding-ийг
// хаадаг дүрэм бүр "ямар ч олдворт тохироогүй" гэж худал анхааруулагдана.
func applyBaseline(r *policy.Result, pol policy.Policy, res finding.ScanResult, path string) (string, int) {
	base, code := loadScan(path)
	if code != 0 {
		return "", code
	}

	d := diff.Compare(base, res)

	var blockers []string
	for _, w := range d.Warnings {
		fmt.Fprintf(os.Stderr, "анхаар: baseline — %s\n", w.Text("mn"))
		if baselineUntrusted[w.Code] {
			blockers = append(blockers, w.Code)
		}
	}
	if len(blockers) > 0 {
		fmt.Fprintf(os.Stderr, "алдаа: baseline итгэх боломжгүй (%s) — ХЭРЭГСЭХГҮЙ, бүх олдворыг тооцно\n",
			strings.Join(blockers, ", "))
		return "(baseline хэрэгсэгдсэнгүй)", 0
	}

	// Шинэ ба дордсон finding-үүд.
	counted := map[string]bool{}
	for _, it := range d.Items {
		if it.Change == diff.ChangeNew || it.Change == diff.ChangeWorsened {
			counted[baselineKey(it.ID, it.CanonicalControl, it.Resource, it.Namespace)] = true
		}
	}

	filtered := res
	filtered.Findings = nil
	for _, f := range res.Findings {
		if counted[baselineKey(f.ID, f.CanonicalControl, f.Resource, f.Namespace)] {
			filtered.Findings = append(filtered.Findings, f)
		}
	}

	// Хоёр дахь үнэлгээ: зөвхөн шинэ/дордсон дээр босго шалгана. Score нь
	// filtered.Summary-аас ирэх тул min_score УРЬДЫН АДИЛ бүтэн кластерын
	// оноогоор шалгагдана — тэр бол baseline-аас хамаарах ёсгүй үнэмлэхүй хэмжүүр.
	nr := pol.Evaluate(filtered, time.Now())
	skipped := len(r.Violations) - len(nr.Violations)

	r.Violations = nr.Violations
	r.Passed = nr.Passed
	r.Reasons = nr.Reasons

	return fmt.Sprintf("baseline: %d өмнөх олдвор тооцоогүй, шинэ+дордсон %d",
		skipped, len(d.Items)-d.Counts[diff.ChangeUnchanged]-d.Counts[diff.ChangeFixed]-d.Counts[diff.ChangeImproved]), 0
}

// baselineKey — diff нь ID хоосон үед canonical түлхүүрт шилждэг тул энд ч мөн
// адил: ID байвал ID, үгүй бол control|resource|namespace.
func baselineKey(id, control, resource, namespace string) string {
	if id != "" {
		return id
	}
	return "k:" + control + "|" + resource + "|" + namespace
}
