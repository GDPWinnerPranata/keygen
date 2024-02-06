const crypto = require("crypto");
const {
  EncryptCommand,
  KMSClient,
  SignCommand,
  GetPublicKeyCommand,
} = require("@aws-sdk/client-kms");
const fs = require("fs");
const env = require("./env");
const { importSPKI, jwtVerify } = require("jose");

main().catch(console.error);

async function main() {
  const signerKeypair = await generateEncryptedKeyPair();
  const encryptKeypair = await generateEncryptedKeyPair();

  console.log("========================================================");
  console.log("|  Generated Keypair");
  console.log("========================================================");
  console.log(JSON.stringify({ signerKeypair, encryptKeypair }, null, 2));
  console.log("\n\n");

  const signerJwt = await sign(signerKeypair);
  const encryptJwt = await sign(encryptKeypair);

  console.log("========================================================");
  console.log("|  Signed Keypair");
  console.log("========================================================");
  console.log(JSON.stringify({ signerJwt, encryptJwt }, null, 2));
  console.log("\n\n");

  const filename = "keys.json";
  const data = JSON.stringify({ signerJwt, encryptJwt }, null, 2);
  fs.writeFileSync(filename, data);

  const signerPublicKey = await getSignerPublicKey();

  console.log("========================================================");
  console.log("|  Signer Public Key");
  console.log("========================================================");
  console.log(signerPublicKey);
  console.log("\n\n");

  const verification = {
    signerJwt: await jwtVerify(signerJwt, await importSPKI(signerPublicKey)),
    encryptJwt: await jwtVerify(encryptJwt, await importSPKI(signerPublicKey)),
  };
  console.log("========================================================");
  console.log("|  Verification Result");
  console.log("========================================================");
  console.log(JSON.stringify({ verification }, null, 2));
  console.log("\n\n");
  console.log("========================================================");
  console.log(`[!] Key generated at '${filename}' successfully!`);
  console.log("========================================================");
}

// =================================== CORE ====================================

async function generateEncryptedKeyPair() {
  const keypair = generateKeyPair();
  const encryptedPrivateKey = await encryptKMS(keypair.privateKey);

  return {
    privateKey: encryptedPrivateKey,
    publicKey: keypair.publicKey,
  };
}

async function sign(payload) {
  const jwtHeader = {
    alg: "ES256",
  };
  const signedString = `${Buffer.from(JSON.stringify(jwtHeader)).toString(
    "base64url"
  )}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}`;

  const kmsClient = getKmsClient();
  const signCommand = new SignCommand({
    Message: new Uint8Array(Buffer.from(signedString)),
    KeyId: env.get("SIGN_KEY_ID"),
    SigningAlgorithm: "ECDSA_SHA_256",
  });

  const generateOutput = await kmsClient.send(signCommand);
  const signature = signatureToBase64(generateOutput.Signature);

  const jwt = `${signedString}.${signature}`;
  return jwt;
}

// =================================== UTILS ===================================

async function getSignerPublicKey() {
  const client = getKmsClient();
  const command = new GetPublicKeyCommand({
    KeyId: env.get("SIGN_KEY_ID"),
  });

  const output = await client.send(command);
  const publicKey = Buffer.from(output.PublicKey).toString("base64");
  return `-----BEGIN PUBLIC KEY-----\n${publicKey
    .match(/.{0,64}/g)
    .join("\n")}-----END PUBLIC KEY-----`;
}

function signatureToBase64(bytes) {
  const rLength = bytes[3];
  const r = bytes.subarray(4, 4 + rLength);
  const s = bytes.subarray(6 + rLength);

  return Buffer.concat([
    Buffer.from(r[0] === 0 ? r.subarray(1) : r),
    Buffer.from(s[0] === 0 ? s.subarray(1) : s),
  ]).toString("base64url");
}

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
  const kmsClient = getKmsClient();

  const encryptCommand = new EncryptCommand({
    Plaintext: new Uint8Array(Buffer.from(plaintext)),
    KeyId: env.get("ENCRYPT_KEY_ID"),
  });

  const encryptionResult = await kmsClient.send(encryptCommand);
  const ciphertext = Buffer.from(encryptionResult.CiphertextBlob).toString(
    "base64"
  );
  return ciphertext;
}

function getKmsClient() {
  return new KMSClient({
    credentials: {
      accessKeyId: env.get("ACCESS_KEY_ID"),
      secretAccessKey: env.get("SECRET_ACCESS_KEY"),
    },
    region: env.get("REGION"),
  });
}
