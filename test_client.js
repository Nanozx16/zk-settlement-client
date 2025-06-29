# zk-settlement-client

const assert = require('assert');
const client = require('../src/client');
const { calculatePedersenHash } = require('../src/common/helper');
const { Request } = require('../src/common/request');

describe('client API test', function () {
    it('generate key pair, sign data, and verify signature', async function () {
        const keys1 = await client.genKeyPair();
        const keys2 = await client.genKeyPair();
        console.log('Result:', keys1, keys2);

        const userAddress = '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd';
        const providerAddress = '0x1234567890123456789012345678901234567890';
        const userAddressBigInt = BigInt(userAddress);
        const providerAddressBigInt = BigInt(providerAddress);

        const requests = [
            new Request(
                '1',
                '5',
                userAddress,
                providerAddress,
                await calculatePedersenHash(BigInt('1'), userAddressBigInt, providerAddressBigInt),
                '2'
            ),
            new Request(
                '2',
                '6',
                userAddress,
                providerAddress,
                await calculatePedersenHash(BigInt('2'), userAddressBigInt, providerAddressBigInt),
                '3'
            ),
            new Request(
                '17325017303560040',
                '7',
                userAddress,
                providerAddress,
                await calculatePedersenHash(
                    BigInt('17325017303560040'),
                    userAddressBigInt,
                    providerAddressBigInt
                ),
                '4'
            ),
        ];
        console.log('requests:', requests);

        const reqSigs = await client.signData(
            requests,
            [keys1.packPrivkey0, keys1.packPrivkey1],
            false
        );
        console.log('signatures:', reqSigs);

        const resSigs = await client.signData(
            requests,
            [keys2.packPrivkey0, keys2.packPrivkey1],
            true
        );
        console.log('signatures:', resSigs);

        let isValid = await client.verifySignature(
            requests,
            reqSigs,
            [keys1.packedPubkey0, keys1.packedPubkey1],
            false
        );
        console.log('isValid:', isValid);
        isValid.forEach((element) => {
            assert.ok(element);
        });

        isValid = await client.verifySignature(
            requests,
            resSigs,
            [keys2.packedPubkey0, keys2.packedPubkey1],
            true
        );
        console.log('isValid:', isValid);
        isValid.forEach((element) => {
            assert.ok(element);
        });
    });
});
