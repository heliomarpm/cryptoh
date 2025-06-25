/**
 * CryptoH - A clean and easy-to-use cryptography helper library for Node.js
 */
import cryptoh, { HashAlgorithm, KeyPair } from "./core/cryptoh";

const {
	/**
	 * Hashing functions for generating and comparing hashes.
	 * @category Functions
	 */
	hash,
	/**
	 * Random number generation functions for generating salts and random values.
	 * @category Functions
	 */
	random,
	/**
	 * Key pair generation functions for creating RSA key pairs.
	 * @category Functions
	 */
	keyPair,
	/**
	 * Digital signature functions for generating and verifying signatures.
	 * @category Functions
	 */
	sign,
} = cryptoh;

export default cryptoh;
export { hash, random, keyPair, sign, KeyPair, HashAlgorithm };
