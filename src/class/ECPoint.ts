import { BigNumber } from 'bignumber.js';
import { ECDSA_CONFIG } from '../common';
import { TAnyNum } from '../types';
import { getInverse, getBN, getModulo } from '../utils';

export class ECPoint {
  public readonly x: BigNumber;
  public readonly y: BigNumber;

  constructor (
    x: TAnyNum,
    y: TAnyNum,
  ) {
    this.x = getBN(x);
    this.y = getBN(y);

    const y2 = this.y.pow(2);

    const x3PxaPb = this.x.pow(3)
      .plus(this.x.multipliedBy(ECDSA_CONFIG.A))
      .plus(ECDSA_CONFIG.B);

    if (!getModulo(x3PxaPb.minus(y2), ECDSA_CONFIG.P).eq(0)) {
      throw new Error('The point is not on the curve.');
    }
  }

  public isEqualTo (point: ECPoint): boolean {
    return point.x.eq(this.x) && point.y.eq(this.y);
  }

  public add (point: ECPoint): ECPoint {
    const alpha: BigNumber = this.isEqualTo(point)
      ? getModulo(
        getBN(this.x.pow(2).multipliedBy(3).plus(ECDSA_CONFIG.A)).multipliedBy(
          getInverse(this.y.multipliedBy(2), ECDSA_CONFIG.P),
        ),
        ECDSA_CONFIG.P,
      )
      : getModulo(
        getBN(point.y.minus(this.y)).multipliedBy(
          getInverse(point.x.minus(this.x), ECDSA_CONFIG.P),
        ),
        ECDSA_CONFIG.P,
      );

    const x: BigNumber = getModulo(
      alpha.pow(2).minus(this.x).minus(point.x),
      ECDSA_CONFIG.P,
    );

    const y: BigNumber = getModulo(
      this.x.minus(x).multipliedBy(alpha).minus(this.y),
      ECDSA_CONFIG.P,
    );

    return new ECPoint(x, y);
  }

  public multiply (t: TAnyNum): ECPoint {
    let times: BigNumber = getBN(t);
    let n: BigNumber = getBN(1);
    let currentPoint: ECPoint = this;
    const usedPoints: { n: BigNumber; point: ECPoint }[] = [];

    if (times.lt(0)) {
      times = times.multipliedBy(-1);
      currentPoint = new ECPoint(this.x, this.y.multipliedBy(-1));
    }

    while (n.lt(times)) {
      usedPoints.push({ n, point: currentPoint });

      if (n.plus(n).isLessThanOrEqualTo(times)) {
        currentPoint = currentPoint.add(currentPoint);
        n = n.plus(n);
      } else {
        const greatestRelevantPoint = usedPoints.reduce((acc, value) =>
          n.plus(value.n).lte(times) &&
          !value.point.x.eq(currentPoint.x)
            ? value
            : acc,
        );

        currentPoint = currentPoint.add(greatestRelevantPoint.point);
        n = n.plus(greatestRelevantPoint.n);
      }
    }

    return currentPoint;
  }
}
