import { BigNumber } from 'bignumber.js';
import { createHash } from 'crypto';
import { ECPoint } from '../class';
import { GENERATOR_POINT } from '../common';
import { TAnyNum } from '../types';

export const PREFIX = '0x';

export const getSHA256 = (text: string): string =>
  PREFIX + createHash('sha256').update(text).digest('hex');

export const getBN = (n: number | string | BigNumber): BigNumber => {
  if (BigNumber.isBigNumber(n)) {
    return n;
  }

  return new BigNumber(n);
};

const xgcdBN = (a: BigNumber, b: BigNumber): [BigNumber, BigNumber] => {
  if (b.eq(0)) {
    return [getBN(1), getBN(0)];
  }

  const [x, y] = xgcdBN(
    b,
    a.minus(a.dividedBy(b).integerValue(BigNumber.ROUND_FLOOR).multipliedBy(b)),
  );

  return [
    y,
    x.minus(y.multipliedBy(a.dividedBy(b).integerValue(BigNumber.ROUND_FLOOR))),
  ];
};

export const getInverse = (number: TAnyNum, modulo: TAnyNum): BigNumber => {
  const [result] = xgcdBN(getBN(number), getBN(modulo));

  return result;
};

export const getModulo = (bn: BigNumber, modulo: BigNumber): BigNumber => {
  if (bn.gte(0)) {
    return bn.mod(modulo);
  }

  return getBN(modulo)
    .minus(bn.multipliedBy(-1).mod(modulo))
    .mod(modulo);
};

export const getLargeRandomNumberAsString = (): string => [0, 0, 0, 0]
  .map(() => Math.floor(Math.random() * 10e15))
  .join('');

export const getSecp256k1Point = (x: BigNumber, y: BigNumber): ECPoint => new ECPoint(x, y);

export const GeneratorPoint: ECPoint = getSecp256k1Point(GENERATOR_POINT.X, GENERATOR_POINT.Y);

export const getPublicKey = (privateKey: string): ECPoint => GeneratorPoint.multiply(privateKey);

export const signMessage = (
  message: string | number,
  privateKey: TAnyNum,
): { s: BigNumber; r: BigNumber } => {
  let k: TAnyNum = getBN(0);
  let r: TAnyNum = getBN(0);

  do {
    k = getLargeRandomNumberAsString();
    const R = GeneratorPoint.multiply(k);
    r = getModulo(R.x, GENERATOR_POINT.ORDER_N);
  } while (r.eq(0));

  const kInverse: BigNumber = getModulo(
    getInverse(k, GENERATOR_POINT.ORDER_N),
    GENERATOR_POINT.ORDER_N,
  );

  const s: BigNumber = getModulo(
    kInverse.multipliedBy(getBN(message).plus(r.multipliedBy(privateKey))),
    GENERATOR_POINT.ORDER_N,
  );

  return { s, r };
};

export const verifySignature = (
  message: number | string,
  { r, s }: { r: BigNumber; s: BigNumber },
  publicKey: ECPoint,
) => {
  const sInverse: BigNumber = getInverse(s, GENERATOR_POINT.ORDER_N);

  const u1: BigNumber = getModulo(
    getBN(message).multipliedBy(sInverse),
    GENERATOR_POINT.ORDER_N,
  );

  const u2: BigNumber = getModulo(getBN(r).multipliedBy(sInverse), GENERATOR_POINT.ORDER_N);

  const c: ECPoint = GeneratorPoint.multiply(u1).add(publicKey.multiply(u2));

  return getModulo(r.minus(c.x), GENERATOR_POINT.ORDER_N).eq(0);
};
