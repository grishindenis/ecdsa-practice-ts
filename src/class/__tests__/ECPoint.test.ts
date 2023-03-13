import {
  getPublicKey,
  getSHA256,
  signMessage,
  verifySignature,
} from '../../utils';

describe('ECPoint', () => {
  it('it signs a message properly', () => {
    const privateKey = '894863200465103420647903018925036145987867353002864184794814255';
    const publicKey = getPublicKey(privateKey);
    const message = 'Hello, World!';
    const messageHash = getSHA256(message);

    const sign = signMessage(messageHash, privateKey);

    const valid = verifySignature(messageHash, sign, publicKey);

    expect(valid).toStrictEqual(true);
  });
});
