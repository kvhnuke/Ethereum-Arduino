/** \file ecdsa.c
  *
  * \brief Contains functions relevant to ECDSA signing.
  *
  * Functions relevant to ECDSA signing include those which perform group
  * operations on points of an elliptic curve (eg. pointAdd() and
  * pointDouble()) and the actual signing function, ecdsaSign().
  *
  * The elliptic curve used is secp256k1, from the document
  * "SEC 2: Recommended Elliptic Curve Domain Parameters" by Certicom
  * research, obtained 11-August-2011 from:
  * http://www.secg.org/collateral/sec2_final.pdf
  * References to RFC 6979 refer to the version dated August 2013, obtained
  * http://tools.ietf.org/html/rfc6979 on 4 April 2015.
  *
  * The operations here are written in a way as to encourage them to run in
  * (mostly) constant time. This provides some resistance against timing
  * attacks. However, the compiler may use optimisations which destroy this
  * property; inspection of the generated assembly code is the only way to
  * check. A disadvantage of this code is that point multiplication is slower
  * than it could be.
  * There are some data-dependent branches in here, but they're expected to
  * only make a difference (in timing) in exceptional cases.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include "common.h"
#include "bignum256.h"
#include "ecdsa.h"
#include "endian.h"
#include "hmac_drbg.h"

/** A point on the elliptic curve, in Jacobian coordinates. The
  * Jacobian coordinates (x, y, z) are related to affine coordinates
  * (x_affine, y_affine) by:
  * (x_affine, y_affine) = (x / (z ^ 2), y / (z ^ 3)).
  *
  * Why use Jacobian coordinates? Because then point addition and
  * point doubling don't have to use inversion (division), which is very slow.
  */
typedef struct PointJacobianStruct
{
	/** x component of a point in Jacobian coordinates. */
	uint8_t x[32];
	/** y component of a point in Jacobian coordinates. */
	uint8_t y[32];
	/** z component of a point in Jacobian coordinates. */
	uint8_t z[32];
	/** If is_point_at_infinity is non-zero, then this point represents the
	  * point at infinity and all other structure members are considered
	  * invalid. */
	uint8_t is_point_at_infinity;
} PointJacobian;

/** The prime number used to define the prime finite field for secp256k1. */
static const uint8_t secp256k1_p[32] = {
0x2f, 0xfc, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

/** 2s complement of #secp256k1_p. */
static const uint8_t secp256k1_complement_p[5] = {
0xd1, 0x03, 0x00, 0x00, 0x01};

/** The order of the base point used in secp256k1. */
const uint8_t secp256k1_n[32] = {
0x41, 0x41, 0x36, 0xd0, 0x8c, 0x5e, 0xd2, 0xbf,
0x3b, 0xa0, 0x48, 0xaf, 0xe6, 0xdc, 0xae, 0xba,
0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

/** 2s complement of #secp256k1_n. */
static const uint8_t secp256k1_complement_n[17] = {
0xbf, 0xbe, 0xc9, 0x2f, 0x73, 0xa1, 0x2d, 0x40,
0xc4, 0x5f, 0xb7, 0x50, 0x19, 0x23, 0x51, 0x45,
0x01};

/** The x component of the base point G used in secp256k1. */
static const uint8_t secp256k1_Gx[32] PROGMEM = {
0x98, 0x17, 0xf8, 0x16, 0x5b, 0x81, 0xf2, 0x59,
0xd9, 0x28, 0xce, 0x2d, 0xdb, 0xfc, 0x9b, 0x02,
0x07, 0x0b, 0x87, 0xce, 0x95, 0x62, 0xa0, 0x55,
0xac, 0xbb, 0xdc, 0xf9, 0x7e, 0x66, 0xbe, 0x79};

/** The y component of the base point G used in secp256k1. */
static const uint8_t secp256k1_Gy[32] PROGMEM = {
0xb8, 0xd4, 0x10, 0xfb, 0x8f, 0xd0, 0x47, 0x9c,
0x19, 0x54, 0x85, 0xa6, 0x48, 0xb4, 0x17, 0xfd,
0xa8, 0x08, 0x11, 0x0e, 0xfc, 0xfb, 0xa4, 0x5d,
0x65, 0xc4, 0xa3, 0x26, 0x77, 0xda, 0x3a, 0x48};

/** Convert a point from affine coordinates to Jacobian coordinates. This
  * is very fast.
  * \param out The destination point (in Jacobian coordinates).
  * \param in The source point (in affine coordinates).
  */
static void affineToJacobian(PointJacobian *out, PointAffine *in)
{
	out->is_point_at_infinity = in->is_point_at_infinity;
	// If out->is_point_at_infinity != 0, the rest of this function consists
	// of dummy operations.
	bigAssign(out->x, in->x);
	bigAssign(out->y, in->y);
	bigSetZero(out->z);
	out->z[0] = 1;
}

/** Convert a point from Jacobian coordinates to affine coordinates. This
  * is very slow because it involves inversion (division).
  * \param out The destination point (in affine coordinates).
  * \param in The source point (in Jacobian coordinates).
  */
static NOINLINE void jacobianToAffine(PointAffine *out, PointJacobian *in)
{
	uint8_t s[32];
	uint8_t t[32];

	out->is_point_at_infinity = in->is_point_at_infinity;
	// If out->is_point_at_infinity != 0, the rest of this function consists
	// of dummy operations.
	bigMultiply(s, in->z, in->z);
	bigMultiply(t, s, in->z);
	// Now s = z ^ 2 and t = z ^ 3.
	bigInvert(s, s);
	bigInvert(t, t);
	bigMultiply(out->x, in->x, s);
	bigMultiply(out->y, in->y, t);
}

/** Double (p = 2 x p) the point p (which is in Jacobian coordinates), placing
  * the result back into p.
  * The formulae for this function were obtained from the article:
  * "Software Implementation of the NIST Elliptic Curves Over Prime Fields",
  * obtained from:
  * http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.25.8619&rep=rep1&type=pdf
  * on 16-August-2011. See equations (2) ("doubling in Jacobian coordinates")
  * from section 4 of that article.
  * \param p The point (in Jacobian coordinates) to double.
  */
static NOINLINE void pointDouble(PointJacobian *p)
{
	uint8_t t[32];
	uint8_t u[32];

	// If p->is_point_at_infinity != 0, then the rest of this function will
	// consist of dummy operations. Nothing else needs to be done since
	// 2O = O.

	// If y is zero then the tangent line is vertical and never hits the
	// curve, therefore the result should be O. If y is zero, the rest of this
	// function will consist of dummy operations.
	p->is_point_at_infinity |= bigIsZero(p->y);

	bigMultiply(p->z, p->z, p->y);
	bigAdd(p->z, p->z, p->z);
	bigMultiply(p->y, p->y, p->y);
	bigMultiply(t, p->y, p->x);
	bigAdd(t, t, t);
	bigAdd(t, t, t);
	// t is now 4.0 * p->x * p->y ^ 2.
	bigMultiply(p->x, p->x, p->x);
	bigAssign(u, p->x);
	bigAdd(u, u, u);
	bigAdd(u, u, p->x);
	// u is now 3.0 * p->x ^ 2.
	// For curves with a != 0, a * p->z ^ 4 needs to be added to u.
	// But since a == 0 in secp256k1, we save 2 squarings and 1
	// multiplication.
	bigMultiply(p->x, u, u);
	bigSubtract(p->x, p->x, t);
	bigSubtract(p->x, p->x, t);
	bigSubtract(t, t, p->x);
	bigMultiply(t, t, u);
	bigMultiply(p->y, p->y, p->y);
	bigAdd(p->y, p->y, p->y);
	bigAdd(p->y, p->y, p->y);
	bigAdd(p->y, p->y, p->y);
	bigSubtract(p->y, t, p->y);
}

/** Add (p1 = p1 + p2) the point p2 to the point p1, storing the result back
  * into p1.
  * Mixed coordinates are used because it reduces the number of squarings and
  * multiplications from 16 to 11.
  * See equations (3) ("addition in mixed Jacobian-affine coordinates") from
  * section 4 of that article described in the comments to pointDouble().
  * junk must point at some memory area to redirect dummy writes to. The dummy
  * writes are used to encourage this function's completion time to be
  * independent of its parameters.
  * \param p1 The point (in Jacobian coordinates) to add p2 to.
  * \param junk Pointer to a dummy variable which may receive dummy writes.
  * \param p2 The point (in affine coordinates) to add to p1.
  */
static NOINLINE void pointAdd(PointJacobian *p1, PointJacobian *junk, PointAffine *p2)
{
	uint8_t s[32];
	uint8_t t[32];
	uint8_t u[32];
	uint8_t v[32];
	uint8_t is_O;
	uint8_t is_O2;
	uint8_t cmp_xs;
	uint8_t cmp_yt;
	PointJacobian *lookup[2];

	lookup[0] = p1;
	lookup[1] = junk;

	// O + p2 == p2.
	// If p1 is O, then copy p2 into p1 and redirect all writes to the dummy
	// write area.
	// The following line does: "is_O = p1->is_point_at_infinity ? 1 : 0;".
	is_O = (uint8_t)((((uint16_t)(-(int)p1->is_point_at_infinity)) >> 8) & 1);
	affineToJacobian(lookup[1 - is_O], p2);
	p1 = lookup[is_O];
	lookup[0] = p1; // p1 might have changed

	// p1 + O == p1.
	// If p2 is O, then redirect all writes to the dummy write area. This
	// preserves the value of p1.
	// The following line does: "is_O2 = p2->is_point_at_infinity ? 1 : 0;".
	is_O2 = (uint8_t)((((uint16_t)(-(int)p2->is_point_at_infinity)) >> 8) & 1);
	p1 = lookup[is_O2];
	lookup[0] = p1; // p1 might have changed

	bigMultiply(s, p1->z, p1->z);
	bigMultiply(t, s, p1->z);
	bigMultiply(t, t, p2->y);
	bigMultiply(s, s, p2->x);
	// The following two lines do: "cmp_xs = bigCompare(p1->x, s) == BIGCMP_EQUAL ? 0 : 0xff;".
	cmp_xs = (uint8_t)(bigCompare(p1->x, s) ^ BIGCMP_EQUAL);
	cmp_xs = (uint8_t)(((uint16_t)(-(int)cmp_xs)) >> 8);
	// The following two lines do: "cmp_yt = bigCompare(p1->y, t) == BIGCMP_EQUAL ? 0 : 0xff;".
	cmp_yt = (uint8_t)(bigCompare(p1->y, t) ^ BIGCMP_EQUAL);
	cmp_yt = (uint8_t)(((uint16_t)(-(int)cmp_yt)) >> 8);
	// The following branch can never be taken when calling pointMultiply(),
	// so its existence doesn't compromise timing regularity.
	if ((cmp_xs | cmp_yt | is_O | is_O2) == 0)
	{
		// Points are actually the same; use point doubling.
		pointDouble(p1);
		return;
	}
	// p2 == -p1 when p1->x == s and p1->y != t.
	// If p1->is_point_at_infinity is set, then all subsequent operations in
	// this function become dummy operations.
	p1->is_point_at_infinity = (uint8_t)(p1->is_point_at_infinity | (~cmp_xs & cmp_yt & 1));
	bigSubtract(s, s, p1->x);
	// s now contains p2->x * p1->z ^ 2 - p1->x.
	bigSubtract(t, t, p1->y);
	// t now contains p2->y * p1->z ^ 3 - p1->y.
	bigMultiply(p1->z, p1->z, s);
	bigMultiply(v, s, s);
	bigMultiply(u, v, p1->x);
	bigMultiply(p1->x, t, t);
	bigMultiply(s, s, v);
	bigSubtract(p1->x, p1->x, s);
	bigSubtract(p1->x, p1->x, u);
	bigSubtract(p1->x, p1->x, u);
	bigSubtract(u, u, p1->x);
	bigMultiply(u, u, t);
	bigMultiply(s, s, p1->y);
	bigSubtract(p1->y, u, s);
}

/** Set field parameters to be those defined by the prime number p which
  * is used in secp256k1. */
static void setFieldToP(void)
{
	bigSetField(secp256k1_p, secp256k1_complement_p, sizeof(secp256k1_complement_p));
}

/** Set field parameters to be those defined by the prime number n which
  * is used in secp256k1. */
void setFieldToN(void)
{
	bigSetField(secp256k1_n, secp256k1_complement_n, sizeof(secp256k1_complement_n));
}

/** Perform scalar multiplication (p = k x p) of the point p by the scalar k.
  * The result will be stored back into p. The multiplication is
  * accomplished by repeated point doubling and adding of the
  * original point. All multi-precision integer operations are done under
  * the prime finite field specified by #secp256k1_p.
  * \param p The point (in affine coordinates) to multiply.
  * \param k The 32 byte multi-precision scalar to multiply p by.
  */
void pointMultiply(PointAffine *p, BigNum256 k)
{
	PointJacobian accumulator;
	PointJacobian junk;
	PointAffine always_point_at_infinity; // for dummy operations
	uint8_t i;
	uint8_t j;
	uint8_t one_byte;
	uint8_t one_bit;
	PointAffine *lookup_affine[2];

	memset(&accumulator, 0, sizeof(PointJacobian));
	memset(&junk, 0, sizeof(PointJacobian));
	memset(&always_point_at_infinity, 0, sizeof(PointAffine));
	setFieldToP();
	// The Montgomery ladder method can't be used here because it requires
	// point addition to be done in pure Jacobian coordinates. Point addition
	// in pure Jacobian coordinates would make point multiplication about
	// 26% slower. Instead, dummy operations are used to make point
	// multiplication a constant time operation. However, the use of dummy
	// operations does make this code more susceptible to fault analysis -
	// by introducing faults where dummy operations may occur, an attacker
	// can determine whether bits in the private key are set or not.
	// So the use of this code is not appropriate in situations where fault
	// analysis can occur.
	accumulator.is_point_at_infinity = 1;
	always_point_at_infinity.is_point_at_infinity = 1;
	lookup_affine[1] = p;
	lookup_affine[0] = &always_point_at_infinity;
	for (i = 31; i < 32; i--)
	{
		one_byte = k[i];
		for (j = 0; j < 8; j++)
		{
			pointDouble(&accumulator);
			one_bit = (uint8_t)((one_byte & 0x80) >> 7);
			pointAdd(&accumulator, &junk, lookup_affine[one_bit]);
			one_byte = (uint8_t)(one_byte << 1);
		}
	}
	jacobianToAffine(p, &accumulator);
}

/** Set a point to the base point of secp256k1.
  * \param p The point to set.
  */
void setToG(PointAffine *p)
{
	uint8_t buffer[32];
	uint8_t i;

	p->is_point_at_infinity = 0;
	for (i = 0; i < 32; i++)
	{
		buffer[i] = LOOKUP_BYTE(secp256k1_Gx[i]);
	}
	bigAssign(p->x, (BigNum256)buffer);
	for (i = 0; i < 32; i++)
	{
		buffer[i] = LOOKUP_BYTE(secp256k1_Gy[i]);
	}
	bigAssign(p->y, (BigNum256)buffer);
}

/** Create a deterministic ECDSA signature of a given message (digest) and
  * private key.
  * This is an implementation of the algorithm described in the document
  * "SEC 1: Elliptic Curve Cryptography" by Certicom research, obtained
  * 15-August-2011 from: http://www.secg.org/collateral/sec1_final.pdf
  * section 4.1.3 ("Signing Operation"). The ephemeral private key "k" will
  * be deterministically generated according to RFC 6979.
  * \param r The "r" component of the signature will be written to here as
  *          a 32 byte multi-precision number.
  * \param s The "s" component of the signature will be written to here, as
  *          a 32 byte multi-precision number.
  * \param hash The message digest of the message to sign, represented as a
  *             32 byte multi-precision number.
  * \param private_key The private key to use in the signing operation,
  *                    represented as a 32 byte multi-precision number.
  */
void printUint(uint8_t *nm, uint8_t vsize){
    int i=0;
    for(;i<vsize;i++)
        printf("%d ",nm[i]);
    printf("\n","");
}
void ecdsaSign(BigNum256 r, BigNum256 s, const BigNum256 hash, const BigNum256 private_key)
{
	PointAffine big_r;
	uint8_t k[32];
	uint8_t seed_material[32 + SHA256_HASH_LENGTH];
	HMACDRBGState state;

	// From RFC 6979, section 3.3a:
	// seed_material = int2octets(private_key) || bits2octets(hash)
	// int2octets and bits2octets both interpret the number as big-endian.
	// However, both the private_key and hash parameters are BigNum256, which
	// is little-endian.
	bigAssign(seed_material, private_key);
	//swapEndian256(seed_material); // little-endian -> big-endian
	bigAssign(&(seed_material[32]), hash);
   //swapEndian256(&(seed_material[32])); // little-endian -> big-endian
	drbgInstantiate(&state, seed_material, sizeof(seed_material));

	while (true)
	{
		drbgGenerate(k, &state, 32, NULL, 0);
		// From RFC 6979, section 3.3b, the output of the DRBG is run through
		// the bits2int function, which interprets the output as a big-endian
		// integer. However, functions in bignum256.c expect a little-endian
		// integer.

		swapEndian256(k); // big-endian -> little-endian
        //printUint(k);
		// This is one of many data-dependent branches in this function. They do
		// not compromise timing attack resistance because these branches are
		// expected to occur extremely infrequently.
		if (bigIsZero(k))
		{
			continue;
		}
		if (bigCompare(k, (BigNum256)secp256k1_n) != BIGCMP_LESS)
		{
			continue;
		}

		// Compute ephemeral elliptic curve key pair (k, big_r).
		setToG(&big_r);
		pointMultiply(&big_r, k);
		//printUint(big_r.x,32);
		//swapEndian256(big_r.x);
		// big_r now contains k * G.
		setFieldToN();
		bigModulo(r, big_r.x);
		//printUint(r,32);
		// r now contains (k * G).x (mod n).
		if (bigIsZero(r))
		{
			continue;
		}
		//swapEndian256(r);
		swapEndian256(private_key);
		bigMultiply(s, r, private_key);
		swapEndian256(hash);
		bigAdd(s, s, hash);
		bigInvert(big_r.y, k);
		bigMultiply(s, s, big_r.y);

		if (bigIsZero(s))
		{
			continue;
		}
		//printUint(s);
		// Canonicalise s by negating it if s > secp256k1_n / 2.
		// See https://github.com/bitcoin/bitcoin/pull/3016 for more info.
		bigShiftRightNoModulo(k, (const BigNum256)secp256k1_n); // use k as temporary
		if (bigCompare(s, k) == BIGCMP_GREATER)
		{
			bigSubtractNoModulo(s, (BigNum256)secp256k1_n, s);
		}
		printUint(s,32);
		break;
	}
}

/** Serialise an elliptic curve point in a manner which is Bitcoin-compatible.
  * This means using the serialisation rules in:
  * "SEC 1: Elliptic Curve Cryptography" by Certicom research, obtained
  * 15-August-2011 from: http://www.secg.org/collateral/sec1_final.pdf
  * sections 2.3.2 ("OctetString-to-BitString Conversion") and
  * 2.3.3 ("EllipticCurvePoint-to-OctetString Conversion").
  * The document basically says that integers should be represented big-endian
  * and that a prefix byte should be prepended to indicate that the public key
  * is compressed or not.
  * \param out Where the serialised point will be written to. This must be a
  *            byte array with space for at least #ECDSA_MAX_SERIALISE_SIZE
  *            bytes.
  * \param point The elliptic point curve to serialise.
  * \param do_compress Whether to apply point compression - this will reduce
  *                    the size of public keys and hence transactions.
  *                    As of 2014, all Bitcoin clients out there are able to
  *                    decompress points, so it should be safe to always
  *                    compress points.
  * \return The number of bytes written to out.
  */
uint8_t ecdsaSerialise(uint8_t *out, const PointAffine *point, const bool do_compress)
{
	PointAffine temp;

	memcpy(&temp, point, sizeof(temp)); // need temp for endian reversing
	if (temp.is_point_at_infinity)
	{
		// Special case for point at infinity.
		out[0] = 0x00;
		return 1;
	}
	else if (!do_compress)
	{
		// Uncompressed point.
		out[0] = 0x04;
		swapEndian256(temp.x);
		swapEndian256(temp.y);
		memcpy(&(out[1]), temp.x, 32);
		memcpy(&(out[33]), temp.y, 32);
		return 65;
	}
	else
	{
		// Compressed point.
		if ((temp.y[0] & 1) != 0)
		{
			out[0] = 0x03; // is odd
		}
		else
		{
			out[0] = 0x02; // is not odd
		}
		swapEndian256(temp.x);
		memcpy(&(out[1]), temp.x, 32);
		return 33;
	}
}
