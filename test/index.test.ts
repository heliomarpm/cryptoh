import { describe, it, expect } from "vitest";
import cryptoh, { HashAlgorithm } from "../src";

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
		const text = 123 as any;
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
		const isValid = await cryptoh.sign.verify(data, signature + "00", publicKey);
		expect(isValid).toBe(false);
	});
});
