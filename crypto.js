const circomlibjs = require('circomlibjs');

let eddsa;
let babyjubjub;
let pedersenHash;

async function init() {
    if (!pedersenHash) {
        pedersenHash = await circomlibjs.buildPedersenHash();
    }
    if (!eddsa) {
        eddsa = await circomlibjs.buildEddsa();
    }
    if (!babyjubjub) {
        babyjubjub = await circomlibjs.buildBabyjub();
    }
}

function babyJubJubGeneratePrivateKey() {
    return babyjubjub.F.random();
}

function babyJubJubGeneratePublicKey(privateKey) {
    return eddsa.prv2pub(privateKey);
}

async function babyJubJubSignature(msg, privateKey) {
    return eddsa.signPedersen(privateKey, msg);
}

async function babyJubJubVerify(msg, signature, publicKey) {
    return eddsa.verifyPedersen(msg, signature, publicKey);
}

function packSignature(signature) {
    return eddsa.packSignature(signature);
}

function packPoint(point) {
    return babyjubjub.packPoint(point);
}

function unpackPoint(point) {
    return babyjubjub.unpackPoint(point);
}

function hash(msg) {
    return pedersenHash.hash(msg);
}

function unpackSignature(signBuff) {
    return eddsa.unpackSignature(signBuff);
}

module.exports = {
    init,
    babyJubJubGeneratePrivateKey,
    babyJubJubGeneratePublicKey,
    babyJubJubSignature,
    babyJubJubVerify,
    packSignature,
    packPoint,
    hash,
    unpackSignature,
    unpackPoint,
};
