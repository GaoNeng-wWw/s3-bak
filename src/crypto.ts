import { createCipheriv, createDecipheriv, createHash, randomBytes, type CipherKey } from 'node:crypto';

const IV_LEN = 16;

/*

+------+-----------------+-----------------+-------+
| IV   |  PLAIN-TEXT-MD5 | CIPHER-TEXT-HASH| CHUNK |
+------+-----------------+-----------------+-------+
| 16   |        16       |       16        |  ...  |
+------+-----------------+-----------------+-------+
*/
export const PLAINTEXT_HASH_OFFSET = [16, 16 + 32] as const;
export const CIPHERTEXT_HASH_OFFSET = [16 + 32, 32 + 16 + 16 + 16] as const;
export const DATACHUNK_OFFSET = 32 + 16 + 16 + 16;
export const encryptFile = (
  chunk: Buffer,
  key: CipherKey,
) => {
  const iv = randomBytes(16);
  const cipher = createCipheriv('aes-256-ctr', key, iv);
  const plainTextHash = Buffer.from(createHash('md5').update(chunk).digest('hex'));
  const cipherText = cipher.update(chunk);
  const cipherTextHash = Buffer.from(createHash('md5').update(cipherText).digest('hex'));
  const final = cipher['final']();
  return Buffer.concat([iv, plainTextHash, cipherTextHash, cipherText, final]);
};
export const decryptFile = (
  chunk: Buffer,
  key: CipherKey,
) => {
  const [PLAINTEXT_START, PLAINTEXT_END] = PLAINTEXT_HASH_OFFSET;
  const [CIPHERTEXT_START, CIPHERTEXT_END] = CIPHERTEXT_HASH_OFFSET;
  const iv = chunk.subarray(0, 16);
  const plainTextHash = chunk.subarray(PLAINTEXT_START, PLAINTEXT_END);
  const cipherTextHash = chunk.subarray(CIPHERTEXT_START, CIPHERTEXT_END);
  const data = chunk.subarray(DATACHUNK_OFFSET);
  const decipher = createDecipheriv('aes-256-ctr', key, iv);
  const plainText = Buffer.concat([
    decipher.update(data),
    decipher['final'](),
  ]);
  return { plainText, plainTextHash, cipherTextHash };
};
