const { importSPKI, jwtVerify } = require("jose");
const { generate, getSignerPublicKey } = require("./generate");

generate(true).then(async ({ signerJwt, encryptJwt }) => {
  const signerPublicKey = await getSignerPublicKey();

  const verification = {
    signerJwt: await jwtVerify(signerJwt, await importSPKI(signerPublicKey)),
    encryptJwt: await jwtVerify(encryptJwt, await importSPKI(signerPublicKey)),
  };
  console.log("========================================================");
  console.log("|  Verification Result");
  console.log("========================================================");
  console.log(JSON.stringify({ verification }, null, 2));
  console.log("\n\n");
});
