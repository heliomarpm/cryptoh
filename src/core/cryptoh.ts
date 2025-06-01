import { createHash, createSign, createVerify, generateKeyPair, randomBytes, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

/**
 * Promisified version of the randomBytes function from the crypto module.
 * @internal
 */
const randomBytesAsync = promisify(randomBytes);

/**
 * Promisified version of the generateKeyPair function from the crypto module.
 * @internal
 */
const generateKeyPairAsync = promisify(generateKeyPair);

/**
 * Represents a key pair consisting of a public key and a private key.
 * The keys are represented as PEM-formatted strings.
 *
 * @property {string} publicKey - The public key in PEM format.
 * @property {string} privateKey - The private key in PEM format.
 *
 * @category Types
 */
export interface KeyPair {
	publicKey: string;
	privateKey: string;
}

/**
 * Enum representing different hash algorithms.
 * Currently supports SHA256, SHA512, and MD5.
 *
 * @category Types
 */
export enum HashAlgorithm {
	SHA1 = "sha1",
	SHA256 = "sha256",
	SHA512 = "sha512",
	MD5 = "md5",
}

/**
 * Validates the input string to ensure it is not empty or whitespace.
 *
 * @param {string} input - The input string to validate.
 * @param {string} [inputName] - An optional name for the input, used in error messages.
 * @throws {Error} Will throw an error if the input is empty or whitespace.
 * @private
 */
function validateInput(input: string, inputName?: string): void {
	if (typeof input !== "string" || input.trim() === "") {
		const name = inputName ? `${inputName.trim()} ` : "";
		throw new Error(`Input ${name}must not be empty or whitespace.`);
	}
}

/**
 * Cryptographic functions for hashing, random number generation, and key pair generation.
 *
 * @category Core
 */
const cryptoh = {
	/**
	 * The default hash algorithm used for hashing operations.
	 * Defaults to SHA512.
	 *
	 * @enum {HashAlgorithm}
	 */
	algorithm: HashAlgorithm,
	/**
	 * Hashing functions for generating and comparing hashes.
	 * @property {function} generate - Generates a hash for the given text using the specified hash algorithm.
	 * @property {function} verify - Compares a given text with a hash to determine if they match.
	 */
	hash: {
		/**
		 * Generates a hash for the given text using the specified hash algorithm.
		 *
		 * @param text - The input text to hash.
		 * @param algorithm - The hash algorithm to use. Defaults to SHA512.
		 * @returns A Promise that resolves to the generated hash as a hexadecimal string.
		 *
		 * @example
		 * ```js
		 * const hashedValue = await cryptor.hash.generate('myPassword');
		 * console.log(hashedValue); // Outputs the hashed value of 'myPassword'
		 * ```
		 */
		async generate(text: string, algorithm: HashAlgorithm = HashAlgorithm.SHA512): Promise<string> {
			validateInput(text, "text");

			const hash = createHash(algorithm);
			hash.update(text);

			return hash.digest("hex");
		},

		/**
		 * Compares a given text with a hash to determine if they match.
		 *
		 * @param text - The input text to compare.
		 * @param hash - The hash to compare against.
		 * @param algorithm - The hash algorithm used for generating the hash. Defaults to SHA512.
		 * @returns A Promise that resolves to `true` if the text matches the hash, `false` otherwise.
		 *
		 * @example
		 * ```js
		 * const isMatch = await cryptor.hash.verify('myPassword', hashedValue);
		 * console.log(isMatch); // Outputs true if the text matches the hash, otherwise false
		 * ```
		 */
		async verify(text: string, hash: string, algorithm: HashAlgorithm = HashAlgorithm.SHA512): Promise<boolean> {
			validateInput(text, "text");
			validateInput(hash, "hash");

			const textBuffer = Buffer.from(await this.generate(text, algorithm), "hex");
			const hashBuffer = Buffer.from(hash, "hex");

			if (textBuffer.length !== hashBuffer.length) return false;
			return timingSafeEqual(textBuffer, hashBuffer);
		},
	},

	/**
	 * Random number generation functions for generating cryptographically secure random values.
	 * @property {function} generateSalt - Generates a random salt value as a hexadecimal string.
	 */
	random: {
		/**
		 * Generates a cryptographically secure random salt value as a hexadecimal string.
		 *
		 * @param length - The length of the salt in bytes. Defaults to 16.
		 * @returns A Promise that resolves to a hexadecimal string representing the generated salt.
		 *
		 * @example
		 * ```js
		 * const salt = await cryptor.random.generateSalt();
		 * console.log(salt); // Outputs a random hexadecimal string of length 16.
		 * ```
		 */
		async generateSalt(length = 16): Promise<string> {
			if (length <= 0) {
				throw new Error("Salt length must be greater than 0.");
			}
			const salt = await randomBytesAsync(length);
			return salt.toString("hex");
		},
	},

	/**
	 * Key pair generation functions for creating RSA key pairs.
	 * @property {function} generate - Generates a new RSA key pair.
	 */
	keyPair: {
		/**
		 * Generates a new 2048-bit RSA key pair and returns it as an object with `publicKey` and `privateKey` properties.
		 *
		 * @returns A Promise that resolves to an object with `publicKey` and `privateKey` properties, both as PEM-formatted strings.
		 *
		 * @example
		 * ```js
		 * const keyPair = await cryptor.keyPair.generate();
		 * console.log(keyPair.publicKey); // Outputs the PEM-formatted public key
		 * console.log(keyPair.privateKey); // Outputs the PEM-formatted private key
		 * ```
		 */
		async generate(): Promise<KeyPair> {
			const { publicKey, privateKey } = await generateKeyPairAsync("rsa", {
				modulusLength: 2048,
				publicKeyEncoding: {
					type: "spki",
					format: "pem",
				},
				privateKeyEncoding: {
					type: "pkcs8",
					format: "pem",
				},
			});

			return { publicKey, privateKey };
		},
	},

	/**
	 * Digital signature functions for signing and verifying data.
	 * @property {function} generate - Generates a digital signature for the given data using the provided private key.
	 * @property {function} verify - Verifies a digital signature against the given data using the public key.
	 */
	sign: {
		/**
		 * Generates a digital signature for the given data using the provided private key.
		 *
		 * @param data - The data to sign.
		 * @param privateKey - The PEM-formatted private key to use for signing.
		 * @param algorithm - The hash algorithm used for signing. Defaults to SHA256.
		 * @returns A Promise that resolves to the generated digital signature as a hexadecimal string.
		 *
		 * @example
		 * ```js
		 * const payload = JSON.stringify({id: 123, nome: "Heliomar", timestamp: Date.now()})
		 * const  { publicKey, privateKey } = await cryptor.keyPair.generate();
		 *
		 * const signature = await cryptor.sign.generate(payload, privateKey);
		 * console.log(Buffer.from(signature).toString("base64"));
		 *
		 * const isValid = await cryptor.sign.verify(payload, signature, publicKey);
		 * console.log(isValid); // Outputs true
		 * ```
		 */
		async generate(data: string, privateKey: string, algorithm: HashAlgorithm = HashAlgorithm.SHA256): Promise<string> {
			validateInput(data, "data");
			validateInput(privateKey, "privateKey");

			const signer = createSign(algorithm);
			signer.update(data);
			return signer.sign(privateKey, "hex");
		},

		/**
		 * Verifies a digital signature against the given data using the public key.
		 *
		 * @param data - The data that was originally signed.
		 * @param signature - The signature to verify.
		 * @param publicKey - The PEM-formatted public key to use for verification.
		 * @param algorithm - The hash algorithm used for signing. Defaults to SHA256.
		 * @returns A Promise that resolves to `true` if the signature is valid, `false` otherwise.
		 *
		 * @example
		 * ```js
		 * const isValid = await cryptor.sign.verify(payload, signature, publicKey);
		 * console.log(isValid); // Outputs true if the signature is valid, otherwise false
		 * ```
		 */
		async verify(data: string, signature: string, publicKey: string, algorithm: HashAlgorithm = HashAlgorithm.SHA256): Promise<boolean> {
			validateInput(data, "data");
			validateInput(signature, "signature");
			validateInput(publicKey, "publicKey");

			const verifier = createVerify(algorithm);
			verifier.update(data);
			return verifier.verify(publicKey, signature, "hex");
		},
	},
};

export default cryptoh;
