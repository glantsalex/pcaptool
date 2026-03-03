// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"github.com/aglants/pcaptool/cmd"
)

func main() {
	printBanner()
	cmd.Execute()
}

func printBanner() {
	const (
		reset  = "\x1b[0m"
		cyan   = "\x1b[36;1m"
		yellow = "\x1b[32m"
		dim    = "\x1b[2m"
	)

	fmt.Println(cyan + "┌──────────────────────────────────────────────────────────────────────────────┐" + reset)
	fmt.Println(cyan + "│" + reset + "   " + cyan + "pcaptool" + reset + " – " + cyan + "Advanced DNS & PCAP Intelligence (v0.x)" + reset + "                         " + cyan + "│" + reset)
	fmt.Println(cyan + "│" + reset + "   " + yellow + "Because \"just scroll it in Wireshark forever\" is not a long-term strategy." + reset + " " + cyan + "│" + reset)
	fmt.Println(cyan + "│" + reset + "   " + yellow + "Multi-pass correlation • Device DNS profiling • Unused/Unresolved DNS" + reset + "      " + cyan + "│" + reset)
	fmt.Println(cyan + "│" + reset + "   " + yellow + "No magic. Just Go, packets, and a healthy dose of paranoia." + reset + "                " + cyan + "│" + reset)
	fmt.Println(cyan + "│" + reset + "                                                                              " + cyan + "│" + reset)
	fmt.Println(cyan + "│" + reset + "                             " + dim + "© 2025 Alex Glants" + reset + "                               " + cyan + "│" + reset)
	fmt.Println(cyan + "└──────────────────────────────────────────────────────────────────────────────┘" + reset)
}
