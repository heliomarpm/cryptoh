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
 * This enum is used to specify the hash algorithm when generating or verifying hashes.
 * It allows for easy selection of the desired algorithm without needing to remember the exact string values.
 *
 * @default SHA512
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
 * @ignore
 */
function _validateInput(input: string, inputName?: string): void {
	if (typeof input !== "string" || input.trim() === "") {
		const name = inputName ? `${inputName.trim()} ` : "";
		throw new Error(`Input ${name}must not be empty or whitespace.`);
	}
}

/**
 * Cryptographic functions for hashing, random number generation, and key pair generation.
 *
 * @example
 * ```ts
 * import cryptoh, { HashAlgorithm } from "cryptoh";
 *
 * async function main() {
 *   // 👤 User registration (secure password storage)
 *   const password = "My$ecureP@ssword123";
 *
 *   // Generate a unique salt for the user
 *   const salt = await cryptoh.random.generateSalt(16);
 *
 *   // Concatenate password + salt and generate the hash
 *   const hashedPassword = await cryptoh.hash.generate(password + salt, HashAlgorithm.SHA512);
 *
 *   console.log("Salt:", salt);
 *   console.log("Hashed password:", hashedPassword);
 *
 *   // You would typically save this salt and hashedPassword to your database
 *   const storedCredentials = { salt, hashedPassword };
 *
 *   // 👤 User login (password verification)
 *   const passwordAttempt = "My$ecureP@ssword123";
 *
 *   // Recreate the hash with the stored salt and compare it to the stored hash
 *   const isPasswordValid = await cryptoh.hash.verify(
 *     passwordAttempt + storedCredentials.salt,
 *     storedCredentials.hashedPassword,
 *     HashAlgorithm.SHA512
 *   );
 *
 *   console.log("Is password valid?", isPasswordValid); // true if matches
 *
 *   // 🔐 Digital signature for sensitive payload (e.g., tokens, receipts, or important data)
 *   const payload = JSON.stringify({
 *     userId: 789,
 *     email: "user@example.com",
 *     timestamp: Date.now()
 *   });
 *
 *   // Generate an RSA key pair
 *   const { publicKey, privateKey } = await cryptoh.keyPair.generate();
 *
 *   // Sign the payload with the private key
 *   const signature = await cryptoh.sign.generate(payload, privateKey);
 *
 *   console.log("Signature (base64):", Buffer.from(signature, "hex").toString("base64"));
 *
 *   // Verify the signature using the public key
 *   const isSignatureValid = await cryptoh.sign.verify(payload, signature, publicKey);
 *
 *   console.log("Is signature valid?", isSignatureValid); // true if signature matches
 * }
 *
 * main();
 * ```
 * @category Core
 * @class
 * @author Heliomar Marques
 */
const cryptoh = {
	/**
	 * The default hash algorithm used for hashing operations.
	 *
	 * @enum {HashAlgorithm}
	 * @category Enumeration
	 * @defaultValue HashAlgorithm.SHA512
	 */
	algorithm: HashAlgorithm,
	/**
	 * Hashing functions for generating and comparing hashes.
	 * @property {function} generate - Generates a hash for the given text using the specified hash algorithm.
	 * @property {function} verify - Compares a given text with a hash to determine if they match.
	 *
	 * @category Hash Functions
	 * @class
	 */
	hash: {
		/**
		 * Generates a hash for the given text using the specified hash algorithm.
		 *
		 * @param text - The input text to hash.
		 * @param algorithm - The hash algorithm to use. Defaults to SHA512.
		 * @returns A Promise that resolves to the generated hash as a hexadecimal string.
		 * @throws {Error} Will throw an error if the input text is empty or whitespace or if the algorithm is not supported.
		 *
		 * @example
		 * ```js
		 * const hashedValue = await cryptor.hash.generate('myPassword');
		 * console.log(hashedValue); // Outputs the hashed value of 'myPassword'
		 * ```
		 *
		 * @category Generate Hash
		 */
		async generate(text: string, algorithm: HashAlgorithm = HashAlgorithm.SHA512): Promise<string> {
			_validateInput(text, "text");

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
		 * @throws {Error} Will throw an error if the input text or hash is empty or whitespace.
		 *
		 * @example
		 * ```js
		 * const isMatch = await cryptor.hash.verify('myPassword', hashedValue);
		 * console.log(isMatch); // Outputs true if the text matches the hash, otherwise false
		 * ```
		 *
		 * @category Verify Hash
		 */
		async verify(text: string, hash: string, algorithm: HashAlgorithm = HashAlgorithm.SHA512): Promise<boolean> {
			_validateInput(text, "text");
			_validateInput(hash, "hash");

			const textBuffer = Buffer.from(await this.generate(text, algorithm), "hex");
			const hashBuffer = Buffer.from(hash, "hex");

			if (textBuffer.length !== hashBuffer.length) return false;
			return timingSafeEqual(textBuffer, hashBuffer);
		},
	},

	/**
	 * Random number generation functions for generating cryptographically secure random values.
	 * @property {function} generateSalt - Generates a random salt value as a hexadecimal string.
	 *
	 * @category Random Functions
	 * @class
	 */
	random: {
		/**
		 * Generates a cryptographically secure random salt value as a hexadecimal string.
		 *
		 * @param length - The length of the salt in bytes. Defaults to 16.
		 * @returns {Promise<string>} A Promise that resolves to a hexadecimal string representing the generated salt.
		 * @throws {Error} Will throw an error if the length is less than or equal to 0.
		 *
		 * @example
		 * ```js
		 * const salt = await cryptor.random.generateSalt();
		 * console.log(salt); // Outputs a random hexadecimal string of length 16.
		 * ```
		 * @category Generate Salt
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
	 *
	 * @category Key Pair Functions
	 * @class
	 */
	keyPair: {
		/**
		 * Generates a new 2048-bit RSA key pair and returns it as an object with `publicKey` and `privateKey` properties.
		 *
		 * @returns A Promise that resolves to an object with `publicKey` and `privateKey` properties, both as PEM-formatted strings.
		 * @throws {Error} Will throw an error if key generation fails.
		 *
		 * @example
		 * ```js
		 * const keyPair = await cryptor.keyPair.generate();
		 * console.log(keyPair.publicKey); // Outputs the PEM-formatted public key
		 * console.log(keyPair.privateKey); // Outputs the PEM-formatted private key
		 * ```
		 * @category Generate Key Pair
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
	 *
	 * @category Signature Functions
	 * @class
	 */
	sign: {
		/**
		 * Generates a digital signature for the given data using the provided private key.
		 *
		 * @param data - The data to sign.
		 * @param privateKey - The PEM-formatted private key to use for signing.
		 * @param algorithm - The hash algorithm used for signing. Defaults to SHA256.
		 * @returns A Promise that resolves to the generated digital signature as a hexadecimal string.
		 * @throws {Error} Will throw an error if the input data or private key is empty or whitespace.
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
		 *
		 * @category Generate Signature
		 */
		async generate(data: string, privateKey: string, algorithm: HashAlgorithm = HashAlgorithm.SHA256): Promise<string> {
			_validateInput(data, "data");
			_validateInput(privateKey, "privateKey");

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
		 * @throws {Error} Will throw an error if the input data, signature, or public key is empty or whitespace.
		 *
		 * @example
		 * ```js
		 * const isValid = await cryptor.sign.verify(payload, signature, publicKey);
		 * console.log(isValid); // Outputs true if the signature is valid, otherwise false
		 * ```
		 *
		 * @category Verify Signature
		 */
		async verify(data: string, signature: string, publicKey: string, algorithm: HashAlgorithm = HashAlgorithm.SHA256): Promise<boolean> {
			_validateInput(data, "data");
			_validateInput(signature, "signature");
			_validateInput(publicKey, "publicKey");

			const verifier = createVerify(algorithm);
			verifier.update(data);
			return verifier.verify(publicKey, signature, "hex");
		},
	},
};

export default cryptoh;
