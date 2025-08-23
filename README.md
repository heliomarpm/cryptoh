<div id="top" align="center">
<h1>

  <img src="./logo.png" alt="Crypto Helper" width="128" />
  <br> Cryptography Helper <a href="https://navto.me/heliomarpm" target="_blank"><img src="https://navto.me/assets/navigatetome-brand.png" width="32"/></a>

  [![DeepScan grade][url-deepscan-badge]][url-deepscan]
  [![CodeFactor][url-codefactor-badge]][url-codefactor]
  [![Test][url-test-badge]][url-test]
  [![Coverage][url-coverage-badge]][url-coverage-report]

  [![NPM version][url-npm-badge]][url-npm]
  [![Downloads][url-downloads-badge]][url-downloads]

  <!-- ![Node.js](https://img.shields.io/badge/node.js-%2343853D.svg?style=for-the-badge&logo=node.js&logoColor=white)
  ![TypeScript](https://img.shields.io/badge/typescript-%23007ACC.svg?style=for-the-badge&logo=typescript&logoColor=white)
  ![Biome](https://img.shields.io/badge/biomejs-%23404d59.svg?style=for-the-badge&logo=biome&logoColor=white)
  ![Semantic Release](https://img.shields.io/badge/semantic_release-%23000000.svg?style=for-the-badge&logo=semantic-release&logoColor=white)
  [![License](https://img.shields.io/github/license/heliomarpm/cryptoh?style=for-the-badge)](./LICENSE) -->

</h1>

<div class="badges">

  [![PayPal][url-paypal-badge]][url-paypal]
  [![Ko-fi][url-kofi-badge]][url-kofi]
  [![Liberapay][url-liberapay-badge]][url-liberapay]
  [![GitHub Sponsors][url-github-sponsors-badge]][url-github-sponsors]
  
</div>
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

### ✏️ Example Code

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

See the [API documentation](https://heliomarpm.github.io/cryptoh) for a complete list of available functions and their signatures.

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

* `npm run check` — runs formatter, linter and import sorting to the requested files
* `npm run format` — run the formatter on a set of files
* `npm run lint` — run various checks on a set of files
* `npm run test` — run unit tests
* `npm run test:c` — run unit tests with coverage
* `npm run docs:dev` — run documentation locally
* `npm run commit` - run conventional commits check
* `npm run release:test` — dry run semantic release 
* `npm run build` — build library


## 📦 Dependencies

✅ Zero runtime dependencies — relies solely on Node.js native crypto module. \
🔄 All devDependencies are pinned to latest stable versions


## 🤝 Contributing

We welcome contributions! Please read:

- [Code of Conduct](docs/CODE_OF_CONDUCT.md)
- [Contributing Guide](docs/CONTRIBUTING.md)

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

[MIT © Heliomar P. Marques](LICENSE)  <a href="#top">🔝</a>

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

<!-- GitHub Actions badges -->
[url-codeql-badge]: https://github.com/heliomarpm/cryptoh/actions/workflows/codeql.yml/badge.svg 
[url-codeql]: https://github.com/heliomarpm/cryptoh/security/code-scanning
[url-test-badge]: https://github.com/heliomarpm/cryptoh/actions/workflows/0.test.yml/badge.svg
[url-test]: https://github.com/heliomarpm/cryptoh/actions/workflows/0.test.yml
[url-coverage-badge2]: https://img.shields.io/badge/coverage-dynamic.svg?label=coverage&color=informational&style=flat&logo=jest&query=$.coverage&url=https://heliomarpm.github.io/cryptoh/coverage-badge.json
[url-coverage-badge]: https://img.shields.io/endpoint?url=https://heliomarpm.github.io/cryptoh/coverage/coverage-badge.json
[url-coverage-report]: https://heliomarpm.github.io/cryptoh/coverage

<!-- https://img.shields.io/endpoint?url=https://heliomarpm.github.io/cryptoh/coverage-badge.json&label=coverage&suffix=%25 -->
[url-release-badge]: https://github.com/heliomarpm/cryptoh/actions/workflows/3.release.yml/badge.svg
[url-release]: https://github.com/heliomarpm/cryptoh/actions/workflows/3.release.yml
[url-publish-badge]: https://github.com/heliomarpm/cryptoh/actions/workflows/4.publish-npm.yml/badge.svg 
[url-publish]: https://github.com/heliomarpm/cryptoh/actions/workflows/4.publish-npm.yml

<!-- other badges -->
[url-npm-badge]: https://img.shields.io/npm/v/@heliomarpm/cryptoh.svg
[url-npm]: https://www.npmjs.com/package/@heliomarpm/cryptoh
[url-downloads-badge]: https://img.shields.io/npm/d18m/@heliomarpm/cryptoh.svg
[url-downloads]: http://badge.fury.io/js/@heliomarpm/cryptoh.svg
[url-deepscan-badge]: https://deepscan.io/api/teams/19612/projects/29822/branches/955507/badge/grade.svg
[url-deepscan]: https://deepscan.io/dashboard#view=project&tid=19612&pid=29822&bid=955507
[url-codefactor-badge]: https://www.codefactor.io/repository/github/heliomarpm/cryptoh/badge
[url-codefactor]: https://www.codefactor.io/repository/github/heliomarpm/cryptoh

