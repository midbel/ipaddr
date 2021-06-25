package main

import (
  "flag"
  "fmt"
  "os"

  "github.com/midbel/ipaddr"
)

func main() {
  flag.Parse()

  ip, err := ipaddr.ParseIP(flag.Arg(0))
  if err != nil {
    fmt.Fprintln(os.Stderr, err)
    os.Exit(1)
  }
  fmt.Printf("address: %s", ip)
  fmt.Println()
  fmt.Printf("class  : %s", ip.Class())
  fmt.Println()
}
