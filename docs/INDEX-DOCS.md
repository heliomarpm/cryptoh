<div id="top" align="center">
  <h1>
  	<br> Cryptography Helper <a href="https://navto.me/heliomarpm" target="_blank"><img src="https://navto.me/assets/navigatetome-brand.png" width="32"/></a>
  </h1>
</div>

## 📚 Summary

A clean and easy-to-use cryptography utility library for Node.js built on top of the native crypto module. It provides modern hashing, secure random generation, RSA key pair management, and digital signature utilities with a clean API.

### Requirements

- Node.js v16+

## 🚀 Features
- 📌 Hash text values using SHA-1, SHA-256, SHA-512, and MD5
- 🔒 Compare hashed values securely using timingSafeEqual
- 🔑 Generate secure RSA 2048-bit key pairs
- ✍️ Create and verify digital signatures
- 🎲 Generate cryptographically secure random salts
- 📝 Fully typed with TypeScript

## 🔧 Usage

**Install the library:**

```bash
npm install @heliomarpm/cryptoh
```

### ✏️ Example Usage

```typescript
import cryptoh, { HashAlgorithm } from "cryptoh";

async function main() {
  // 👤 User registration (secure password storage)
  const password = "My$ecureP@ssword123";

  // Generate a unique salt for the user
  const salt = await cryptoh.random.generateSalt(16);

  // Concatenate password + salt and generate the hash
  const hashedPassword = await cryptoh.hash.generate(password + salt, HashAlgorithm.SHA512);

  console.log("Salt:", salt);
  console.log("Hashed password:", hashedPassword);

  // You would typically save this salt and hashedPassword to your database
  const storedCredentials = { salt, hashedPassword };

  // 👤 User login (password verification)
  const passwordAttempt = "My$ecureP@ssword123";

  // Recreate the hash with the stored salt and compare it to the stored hash
  const isPasswordValid = await cryptoh.hash.verify(
    passwordAttempt + storedCredentials.salt,
    storedCredentials.hashedPassword,
    HashAlgorithm.SHA512
  );

  console.log("Is password valid?", isPasswordValid); // true if matches

  // 🔐 Digital signature for sensitive payload (e.g., tokens, receipts, or important data)
  const payload = JSON.stringify({
    userId: 789,
    email: "user@example.com",
    timestamp: Date.now()
  });

  // Generate an RSA key pair
  const { publicKey, privateKey } = await cryptoh.keyPair.generate();

  // Sign the payload with the private key
  const signature = await cryptoh.sign.generate(payload, privateKey);

  console.log("Signature (base64):", Buffer.from(signature, "hex").toString("base64"));

  // Verify the signature using the public key
  const isSignatureValid = await cryptoh.sign.verify(payload, signature, publicKey);

  console.log("Is signature valid?", isSignatureValid); // true if signature matches
}

main();
```

## 📚 API Reference

### 🔒 cryptoh.hash

- Hashes the given text using the specified algorithm (default: SHA-256). \
`generate(text: string, algorithm?: HashAlgorithm): Promise<string>`

- Securely compares a plain text value with a given hash. \
`verify(text: string, hash: string, algorithm?: HashAlgorithm): Promise<boolean>`


### 🎲 cryptoh.random

- Generates a cryptographically secure random salt as a hex string. Default length: 16 bytes. \
`generateSalt(length?: number): Promise<string>`


### 🔑 cryptoh.keyPair

- Generates a 2048-bit RSA key pair with PEM encoding. \
`generate(): Promise<{ publicKey: string, privateKey: string }>`

### ✍️ cryptoh.sign

- Generates a digital signature for the provided data using the private key. \
`generate(data: string, privateKey: string, algorithm?: HashAlgorithm): Promise<string>`

- Verifies the authenticity of a digital signature. \
`verify(data: string, signature: string, publicKey: string, algorithm?: HashAlgorithm): Promise<boolean>`


## 📦 Project Scripts

* `npm run lint` — run linter and fixer
* `npm run format` — run formatter
* `npm run test` — run unit tests
* `npm run test:c` — run unit tests with coverage
* `npm run commit` - run conventional commits check
* `npm run release:test` — dry run semantic release 
* `npm run build` — build library


## 📦 Dependencies

✅ Zero runtime dependencies — relies solely on Node.js native crypto module. \
🔄 All devDependencies are pinned to latest stable versions


## 🤝 Contributing

We welcome contributions! Please read:

- [Code of Conduct](./CODE_OF_CONDUCT.md)
- [Contributing Guide](./CONTRIBUTING.md)

Thank you to everyone who has already contributed to the project!

<a href="https://github.com/heliomarpm/cryptoh/graphs/contributors" target="_blank">
  <!-- <img src="https://contrib.rocks/image?repo=heliomarpm/cryptoh" /> -->
  <img src="https://contrib.nn.ci/api?repo=heliomarpm/cryptoh&no_bot=true" />
</a>

<!-- ###### Made with [contrib.rocks](https://contrib.rocks). -->
###### Made with [contrib.nn](https://contrib.nn.ci).

### ❤️ Support this project

If this project helped you in any way, there are several ways to contribute. \
Help us maintain and improve this template:

⭐ Starring the repository \
🐞 Reporting bugs \
💡 Suggest features \
🧾 Improving the documentation \
📢 Share with others

💵 Supporting via GitHub Sponsors, Ko-fi, Paypal or Liberapay, you decide. 😉

<div class="badges">

  [![PayPal][url-paypal-badge]][url-paypal]
  [![Ko-fi][url-kofi-badge]][url-kofi]
  [![Liberapay][url-liberapay-badge]][url-liberapay]
  [![GitHub Sponsors][url-github-sponsors-badge]][url-github-sponsors]

</div>


## 📝 License

[MIT © Heliomar P. Marques](./LICENSE.md)  <a href="#top">🔝</a>

----
<!-- Sponsor badges -->
[url-paypal-badge]: https://img.shields.io/badge/donate%20on-paypal-1C1E26?style=for-the-badge&labelColor=1C1E26&color=0475fe
[url-paypal]: https://bit.ly/paypal-sponsor-heliomarpm

[url-kofi-badge]: https://img.shields.io/badge/kofi-1C1E26?style=for-the-badge&labelColor=1C1E26&color=ff5f5f
[url-kofi]: https://ko-fi.com/heliomarpm

[url-liberapay-badge]: https://img.shields.io/badge/liberapay-1C1E26?style=for-the-badge&labelColor=1C1E26&color=f6c915
[url-liberapay]: https://liberapay.com/heliomarpm

[url-github-sponsors-badge]: https://img.shields.io/badge/GitHub%20-Sponsor-1C1E26?style=for-the-badge&labelColor=1C1E26&color=db61a2
[url-github-sponsors]: https://github.com/sponsors/heliomarpm
