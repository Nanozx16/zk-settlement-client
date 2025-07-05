const crypto = require('./common/crypto');
const utils = require('./common/utils');
const helper = require('./common/helper');

async function genKeyPair() {
    await crypto.init();

    const privkey = crypto.babyJubJubGeneratePrivateKey();
    const pubkey = crypto.babyJubJubGeneratePublicKey(privkey);

    const packedPubkey = crypto.packPoint(pubkey);
    const packedPubkey0 = utils.bytesToBigint(packedPubkey.slice(0, 16));
    const packedPubkey1 = utils.bytesToBigint(packedPubkey.slice(16));
    const packPrivkey0 = utils.bytesToBigint(privkey.slice(0, 16));
    const packPrivkey1 = utils.bytesToBigint(privkey.slice(16));
    return { packPrivkey0, packPrivkey1, packedPubkey0, packedPubkey1 };
}

async function genCombinedKey(privkey0, privkey1) {
    const packedPrivkey0 = utils.bigintToBytes(privkey0, 16);
    const packedPrivkey1 = utils.bigintToBytes(privkey1, 16);
    const combinedKey = new Uint8Array(32);
    combinedKey.set(packedPrivkey0, 0);
    combinedKey.set(packedPrivkey1, 16);
    return combinedKey;
}

async function signData(data, privKey, signResponse) {
    const combinedKey = await genCombinedKey(privKey[0], privKey[1]);

    return await helper.signRequests(data, combinedKey, signResponse);
}

async function verifySignature(data, sig, pubKey, signResponse) {
    return await helper.verifySig(data, sig, pubKey, signResponse);
}

module.exports = {
    genKeyPair,
    signData,
    verifySignature,
};
