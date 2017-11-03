package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

const (
	PATCH_PREFIX = "patch_"
)

func main() {
	files, err := ioutil.ReadDir(os.Args[1])
	if err != nil {
		panic(err)
	}

	dirs := []string{}
	for _, file := range files {
		if file.IsDir() && strings.HasPrefix(file.Name(), PATCH_PREFIX) {
			dirs = append(dirs, file.Name())
		}
	}

	generate(dirs)
}

func generate(dirs []string) {
	fmt.Println("install:")
	fmt.Printf("\t@echo -e \"\\033[31;1m install patch set begin \\033[0m\"\n")
	for _, d := range dirs {
		fmt.Printf("\t$(MAKE) -C %s install\n", d)
	}
	fmt.Printf("\t@echo -e \"\\033[32;1m install patch set end \\033[0m\"\n")
	fmt.Println()
	fmt.Println("uninstall:")
	fmt.Printf("\t@echo -e \"\\033[31;1m uninstall patch set begin \\033[0m\"\n")
	for i := range dirs {
		fmt.Printf("\t$(MAKE) -C %s uninstall\n", dirs[len(dirs)-1-i])
	}
	fmt.Printf("\t@echo -e \"\\033[32;1m uninstall patch set end \\033[0m\"\n")
}
