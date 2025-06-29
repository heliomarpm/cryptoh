import { describe, expect, it } from "vitest";
import cryptoh, { HashAlgorithm } from "../src";

describe("cryptoh usecase", () => {
	it("real use case", async () => {
		// 👤 User registration (secure password storage)
		const password = "My$ecureP@ssword123";

		// Generate a unique salt for the user
		const salt = await cryptoh.random.generateSalt(16);
		expect(salt).toBeTypeOf("string");
		expect(salt.length).toBe(32); // 16 bytes in hex

		// Concatenate password + salt and generate the hash
		const hashedPassword = await cryptoh.hash.generate(password + salt, HashAlgorithm.SHA512);
		expect(hashedPassword).toBeTypeOf("string");
		expect(hashedPassword.length).toBe(128); // SHA512 produces a 64

		// You would typically save this salt and hashedPassword to your database
		const storedCredentials = { salt, hashedPassword };

		// Recreate the hash with the stored salt and compare it to the stored hash
		const isPasswordValid = await cryptoh.hash.verify(password + storedCredentials.salt, storedCredentials.hashedPassword, HashAlgorithm.SHA512);
		expect(isPasswordValid).toBe(true);

		// 🔐 Digital signature for sensitive payload (e.g., tokens, receipts, or important data)
		const payload = JSON.stringify({
			userId: 789,
			email: "user@example.com",
			timestamp: Date.now(),
		});

		// Generate an RSA key pair
		const { publicKey, privateKey } = await cryptoh.keyPair.generate();
		expect(publicKey).toBeTypeOf("string");
		expect(privateKey).toBeTypeOf("string");

		// Sign the payload with the private key
		const signature = await cryptoh.sign.generate(payload, privateKey);
		expect(signature).toBeTypeOf("string");
		expect(signature.length).toBeGreaterThan(0); // Signature should not be empty
		expect(signature.length).toBeLessThanOrEqual(512); // RSA signatures are typically less than

		const base64Signature = Buffer.from(signature, "hex").toString("base64");
		expect(base64Signature).toBeTypeOf("string");
		expect(base64Signature.length).toBeGreaterThan(0); // Base64 signature should not be empty
		expect(base64Signature.length).toBeLessThanOrEqual(768); // Base64 signature length can vary

		// Verify the signature using the public key
		const isSignatureValid = await cryptoh.sign.verify(payload, signature, publicKey);
		expect(isSignatureValid).toBe(true);
	});
});

describe("cryptoh.hash", () => {
	it("should generate a hash with default algorithm (SHA512)", async () => {
		const text = "myPassword";
		const hash = await cryptoh.hash.generate(text);
		expect(hash).toBeTypeOf("string");
		expect(hash.length).toBeGreaterThan(0);
	});

	it("should generate a hash with custom algorithm (SHA256)", async () => {
		const text = "myPassword";
		const algorithm = HashAlgorithm.SHA256;
		const hash = await cryptoh.hash.generate(text, algorithm);
		expect(hash).toBeTypeOf("string");
		expect(hash.length).toBeGreaterThan(0);
	});

	it("should work with different hash algorithms", async () => {
		const text = "myPassword";
		const hash = await cryptoh.hash.generate(text, HashAlgorithm.SHA256);
		const result = await cryptoh.hash.verify(text, hash, HashAlgorithm.SHA256);
		expect(result).toBe(true);
	});

	it("should throw an error with invalid algorithm", async () => {
		const text = "myPassword";
		const algorithm = " invalid-algorithm" as HashAlgorithm;
		await expect(cryptoh.hash.generate(text, algorithm)).rejects.toThrow();
	});

	it("should throw an error with empty input text", async () => {
		const text = "";
		await expect(cryptoh.hash.generate(text)).rejects.toThrow();
	});

	it("should throw an error with whitespace input text", async () => {
		const text = "   ";
		await expect(cryptoh.hash.generate(text)).rejects.toThrow();
	});
	it("should generate a hash", async () => {
		const result = await cryptoh.hash.generate("test");
		expect(result).toBeTypeOf("string");
		expect(result.length).toBeGreaterThan(0);
	});

	it("should compare a valid hash successfully", async () => {
		const text = "mySecret";
		const hash = await cryptoh.hash.generate(text);
		const match = await cryptoh.hash.verify(text, hash);
		expect(match).toBe(true);
	});

	it("should return false for non-matching text and hash", async () => {
		const match = await cryptoh.hash.verify("test", "invalidhash");
		expect(match).toBe(false);
	});

	it("should support different algorithms", async () => {
		const sha512Hash = await cryptoh.hash.generate("test", cryptoh.algorithm.SHA512);
		expect(sha512Hash).toBeTypeOf("string");
		expect(sha512Hash.length).toBeGreaterThan(0);
	});
	it("should throw an error for empty text", async () => {
		const text = "";
		const hash = "someHash";
		await expect(cryptoh.hash.verify(text, hash)).rejects.toThrow();
	});

	it("should throw an error for empty hash", async () => {
		const text = "myPassword";
		const hash = "";
		await expect(cryptoh.hash.verify(text, hash)).rejects.toThrow();
	});

	it("should throw an error for non-string input", async () => {
		const text = 123 as never;
		const hash = "someHash";
		await expect(cryptoh.hash.verify(text, hash)).rejects.toThrow();
	});
});

describe("cryptoh.random", () => {
	it("should generate a salt of default length", async () => {
		const salt = await cryptoh.random.generateSalt();
		expect(salt).toBeTypeOf("string");
		expect(salt.length).toBe(32); // 16 bytes em hex
	});

	it("should generate a salt of custom length", async () => {
		const salt = await cryptoh.random.generateSalt(8);
		expect(salt.length).toBe(16); // 8 bytes em hex
	});

	it("should throw error if length <= 0", async () => {
		await expect(() => cryptoh.random.generateSalt(0)).rejects.toThrow();
	});
});

describe("cryptoh.keyPair", () => {
	it("should generate a valid key pair", async () => {
		const { publicKey, privateKey } = await cryptoh.keyPair.generate();
		expect(publicKey).toContain("BEGIN PUBLIC KEY");
		expect(privateKey).toContain("BEGIN PRIVATE KEY");
	});
});

describe("cryptoh.sign", () => {
	it("should generate and verify a valid signature", async () => {
		const data = "secure message";
		const { publicKey, privateKey } = await cryptoh.keyPair.generate();

		const signature = await cryptoh.sign.generate(data, privateKey);
		expect(signature).toBeTypeOf("string");

		const isValid = await cryptoh.sign.verify(data, signature, publicKey);
		expect(isValid).toBe(true);
	});

	it("should fail verification with wrong signature", async () => {
		const data = "secure message";
		const { publicKey, privateKey } = await cryptoh.keyPair.generate();

		const signature = await cryptoh.sign.generate(data, privateKey);
		const isValid = await cryptoh.sign.verify(data, `${signature}00`, publicKey);
		expect(isValid).toBe(false);
	});
});
