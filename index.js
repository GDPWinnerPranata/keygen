const crypto = require("crypto");
const { EncryptCommand, KMSClient } = require("@aws-sdk/client-kms");
const { SignJWT, importPKCS8 } = require("jose");
const fs = require("fs");
const env = require("./env");

function generateKeyPair() {
  const {
    privateKey,
    publicKey: { kty, crv, ...publicKey },
  } = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
    publicKeyEncoding: {
      type: "spki",
      format: "jwk",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
    },
  });

  return {
    publicKey,
    privateKey,
  };
}

async function encryptKMS(plaintext) {
  const kmsClient = new KMSClient({
    credentials: {
      accessKeyId: env.get("ACCESS_KEY_ID"),
      secretAccessKey: env.get("SECRET_ACCESS_KEY"),
    },
    region: env.get("REGION"),
  });

  const encryptCommand = new EncryptCommand({
    Plaintext: new Uint8Array(Buffer.from(plaintext)),
    KeyId: env.get("KEY_ID"),
  });

  const encryptionResult = await kmsClient.send(encryptCommand);
  const ciphertext = Buffer.from(encryptionResult.CiphertextBlob).toString(
    "base64"
  );
  return ciphertext;
}

async function generateEncryptedKeyPair() {
  const keypair = generateKeyPair();
  const encryptedPrivateKey = await encryptKMS(keypair.privateKey);

  return {
    keypair: {
      privateKey: encryptedPrivateKey,
      publicKey: keypair.publicKey,
    },
    decryptedPrivateKey: keypair.privateKey,
  };
}

async function sign(payload, privateKey) {
  const secret = await importPKCS8(privateKey);
  const jwt = await new SignJWT(payload)
    .setProtectedHeader({
      alg: "ES256",
    })
    .sign(secret);

  return jwt;
}

async function main() {
  const signerKeypair = await generateEncryptedKeyPair();
  const encryptKeypair = await generateEncryptedKeyPair();

  const signerJwt = await sign(
    signerKeypair.keypair,
    signerKeypair.decryptedPrivateKey
  );
  const encryptJwt = await sign(
    encryptKeypair.keypair,
    signerKeypair.decryptedPrivateKey
  );

  const filename = "keys.json";
  const data = JSON.stringify({ signerJwt, encryptJwt }, null, 2);
  fs.writeFileSync(filename, data);

  console.log(data);
  console.log();
  console.log(`[!] Key generated at '${filename}' successfully!`);
}

main().catch(console.error);
