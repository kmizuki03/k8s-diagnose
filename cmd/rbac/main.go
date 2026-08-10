package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/kmizuki03/k8s-diagnose/internal/rbac"
	"github.com/kmizuki03/k8s-diagnose/internal/redact"
)

func main() {
	namespace := flag.String("namespace", "default", "Roleに設定するnamespace")
	output := flag.String("output-dir", "rbac", "YAML出力先")
	check := flag.Bool("check", false, "既存YAMLとルール定義の一致だけ確認")
	flag.Parse()
	if err := rbac.Write(*output, *namespace, *check); err != nil {
		fmt.Fprintln(os.Stderr, "エラー:", redact.MaskSecrets(err.Error()))
		os.Exit(1)
	}
}
