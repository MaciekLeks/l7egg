package main

import (
	"fmt"
	"github.com/MaciekLeks/l7egg/pkg/apis/maciekleks.dev/v1alpha1"
)

func main() {
	cegg := v1alpha1.ClusterEgg{}
	fmt.Printf("Just show: %v", cegg)
}
