package password

import (
	"fmt"
	"log"
	"testing"
)

func Test(t *testing.T) {
	password := []byte(
		"super_secret_password",
	)
	timeCost := uint32(2)
	memoryCost := uint32(64 * 1024)
	threads := uint8(4) // 4 threads
	hash, err := Hash(
		password,
		timeCost,
		memoryCost,
		threads,
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf(
		"Hashed password: %x\n",
		hash,
	)
	if Verify(
		hash,
		password,
		timeCost,
		memoryCost,
		threads,
	) == 0 {
		t.Fatal("FAIL")
	}
	println("Verify password: SUCCESS")
}
