package password

import (
        "crypto/rand"
        "crypto/subtle"

        "golang.org/x/crypto/argon2"
)

const (
        saltLen = 16
        keyLen  = 32
        hashLen = saltLen + keyLen
)

func Hash(
        password []byte,
        timeCost,
        memoryCost uint32,
        threads uint8,
) (hash [hashLen]byte, err error) {
        //generate salt
        if _, err = rand.Read(
                hash[:saltLen],
        ); err != nil {
                return
        }
        // Hash the password
        copy(hash[saltLen:], argon2.IDKey(
                password,
                hash[:saltLen],
                timeCost,
                memoryCost,
                threads,
                keyLen,
        ))
        return
}
func Verify(
        hash [hashLen]byte,
        password []byte,
        timeCost,
        memoryCost uint32,
        threads uint8,
) int {
        // Use constant-time comparison to prevent timing attacks
        return subtle.ConstantTimeCompare(
                hash[saltLen:],
                // Hash the provided password with the same parameters
                argon2.IDKey(
                        password,
                        hash[:saltLen], // salt
                        timeCost,
                        memoryCost,
                        threads,
                        keyLen,
                ),
        )
}
