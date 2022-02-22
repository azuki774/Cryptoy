package genrsa

import (
	"crypto/rsa"
	"math/big"
)

var bigOne = big.NewInt(1)

// modified crypto/rsa/GenerateMultiPrimeKey
func GeneratePrivateKey(p1 *big.Int, p2 *big.Int, inputE int) (*rsa.PrivateKey, error) {
	priv := new(rsa.PrivateKey)
	priv.E = inputE
	primes := []*big.Int{p1, p2}

	n := new(big.Int).Set(bigOne)
	totient := new(big.Int).Set(bigOne)
	pminus1 := new(big.Int)
	for _, prime := range primes {
		n.Mul(n, prime)
		pminus1.Sub(prime, bigOne)
		totient.Mul(totient, pminus1)
	}

	priv.D = new(big.Int)
	e := big.NewInt(int64(priv.E))
	priv.D.ModInverse(e, totient)

	priv.Primes = primes
	priv.N = n

	priv.Precompute()
	return priv, nil
}
