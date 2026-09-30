// Package cli implements the TATAR-Kuber command dispatch.
// Skeleton нь stdlib (flag)-ээр; production-д spf13/cobra руу шилжинэ.
package cli

import (
	"fmt"
	"os"
)

// Version — build-time-д тохируулагдана (-ldflags).
var Version = "1.0.3-dev"

// Execute — entrypoint.
func Execute() int {
	// Хэлийг эхлээд: usage болон "тодорхойгүй команд" хоёр нь команд сонгогдохоос
	// ӨМНӨ хэвлэгддэг тул `tatar-kuber --lang mn --help` ажиллах ёстой.
	if _, code := setLang(os.Args[1:]); code != 0 {
		return code
	}
	if len(os.Args) < 2 {
		fmt.Print(msg("usage"))
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
		fmt.Fprintln(os.Stderr, msg("cmd.update.todo"))
		return 2
	case "version":
		fmt.Printf("TATAR-Kuber %s\n", Version)
		return 0
	case "-h", "--help", "help":
		fmt.Print(msg("usage"))
		return 0
	default:
		fmt.Fprintf(os.Stderr, "%s\n\n", msg("err.command.unknown", os.Args[1]))
		fmt.Print(msg("usage"))
		return 3
	}
}
