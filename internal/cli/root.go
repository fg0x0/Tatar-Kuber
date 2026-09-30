// Package cli implements the TATAR-Kuber command dispatch.
// Skeleton нь stdlib (flag)-ээр; production-д spf13/cobra руу шилжинэ.
package cli

import (
	"fmt"
	"os"
)

// Version — build-time-д тохируулагдана (-ldflags).
var Version = "1.0.3-dev"

const usage = `TATAR-Kuber — Kubernetes security posture assessment framework

Ашиглах:
  tatar-kuber <command> [flags]

Commands:
  scan      Cluster/manifest шалгах эсвэл цуглуулсан raw-г нэгтгэж scan-result.json үүсгэнэ
  report    scan-result.json-оос тайлан (json|sarif|html) үүсгэнэ; --lang-аар хэлийг сэлгэнэ
  gate      scan-result.json-ыг .tatar-kuber.yaml бодлоготой тулгаж CI-д pass/fail (exit code);
            --baseline-тай хамт --lang-аар анхааруулгын хэлийг сэлгэнэ (en|mn)
  diff      Хоёр scan-result.json-ыг тулгаж юу шинэ / зассан / дордсоныг харуулна
  doctor    Scanner binary-ууд суусан эсэх, хувилбар, горимыг шалгана
  verify-lab expected-findings.json-той тулгаж regression шалгана
  update    (төлөвлөсөн, v2) Scanner binary-уудыг татаж, баталгаажуулж шинэчилнэ
  version   Хувилбар харуулна

Жишээ:
  tatar-kuber doctor
  tatar-kuber scan --kubeconfig ~/.kube/config --namespace prod --out-dir ./out   # Live Mode B
  tatar-kuber scan --raw-dir ./raw --cluster prod --out-dir ./out                 # Offline (Mode A)
  tatar-kuber report --input ./out/scan-result.json --format html --out report.html
  tatar-kuber report --input ./out/scan-result.json --format html --lang mn --out mn.html # нэг scan, өөр хэл
  tatar-kuber gate --input ./out/scan-result.json --fail-on high              # CI gate
  tatar-kuber diff --old ./prev/scan-result.json --new ./out/scan-result.json # Trending

Тэмдэглэл: scan-ийн --out-dir нь ХАВТАС, report/diff-ийн --format нь ФОРМАТ.
Хоёул -o гэсэн хуучин бичиглэлээ хэвээр хүлээж авна (CI эвдрэхгүй).

Exit code (CI-д хамаарна):
  0  амжилттай / gate давсан
  1  бодлого эсвэл босго зөрчигдсөн — gate, diff --fail-on-new,
     report --fail-on, verify-lab FAIL, doctor (ямар ч scanner суугаагүй)
  2  ажиллагааны алдаа — оролт уншигдсангүй/эвдэрсэн, эсвэл танигдаагүй флаг
     (танигдаагүй флагийг Go-ийн flag parser команд ажиллахаас өмнө буцаана)
  3  хэрэглээний алдаа — команд, формат, хэл танигдсангүй, эсвэл заавал флаг дутуу
`

// Execute — entrypoint.
func Execute() int {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		return 3
	}
	switch os.Args[1] {
	case "scan":
		return cmdScan(os.Args[2:])
	case "report":
		return cmdReport(os.Args[2:])
	case "doctor":
		return cmdDoctor(os.Args[2:])
	case "gate":
		return cmdGate(os.Args[2:])
	case "diff":
		return cmdDiff(os.Args[2:])
	case "verify-lab":
		return cmdVerifyLab(os.Args[2:])
	case "update":
		fmt.Fprintln(os.Stderr, "update: v1-д хэрэгжээгүй (төлөвлөгөө: download -> checksum/cosign баталгаажуулалт -> tools.lock.yaml). Одоогоор scanner-уудыг өөрөө суулгаж `tatar-kuber doctor`-оор шалгана уу.")
		return 2
	case "version":
		fmt.Printf("TATAR-Kuber %s\n", Version)
		return 0
	case "-h", "--help", "help":
		fmt.Print(usage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "тодорхойгүй команд: %s\n\n", os.Args[1])
		fmt.Print(usage)
		return 3
	}
}
