import { describe, it, expect } from 'vitest';
import { encryptFile, decryptFile, CIPHERTEXT_HASH_OFFSET, DATACHUNK_OFFSET } from '../crypto';
import { createHash, randomBytes } from 'node:crypto';

describe('crypto module', () => {
  const key = randomBytes(32); // AES-256 key length
  const data = Buffer.from('This is a test data');

  it('should encrypt and decrypt data correctly', () => {
    const encrypted = encryptFile(data, key);
    const { plainText, plainTextHash, cipherTextHash } = decryptFile(encrypted, key);
    expect(plainText).toStrictEqual(data);
    expect(plainTextHash.toString()).toEqual(createHash('md5').update(data).digest('hex'));
    const start = DATACHUNK_OFFSET;
    expect(cipherTextHash.toString()).toEqual(createHash('md5').update(encrypted.subarray(start)).digest('hex'));
  });

  it('should produce different ciphertexts for the same plaintext with different IVs', () => {
    const encrypted1 = encryptFile(data, key);
    const encrypted2 = encryptFile(data, key);

    expect(encrypted1).not.toStrictEqual(encrypted2);
  });

  it('should fail to decrypt if data is tampered with', () => {
    const encrypted = encryptFile(data, key);
    encrypted[DATACHUNK_OFFSET]! ^= 1;

    const { plainText, plainTextHash, cipherTextHash } = decryptFile(encrypted, key);
    expect(plainText).not.toStrictEqual(data);
    expect(plainTextHash.toString()).toEqual(createHash('md5').update(data).digest('hex'));
    const start = DATACHUNK_OFFSET;
    expect(cipherTextHash.toString()).not.toEqual(createHash('md5').update(encrypted.subarray(start)).digest('hex'));
  });
});
