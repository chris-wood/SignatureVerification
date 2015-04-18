// verifier.cpp - written and placed in the public domain by Wei Dai
// g++ -o verifier verifier.cpp libcryptopp.a

#include "dll.h"
#include "pch.h"

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "rsa.h"
#include "md2.h"
#include "nr.h"
#include "dsa.h"
#include "dh.h"
#include "mqv.h"
#include "luc.h"
#include "xtrcrypt.h"
#include "rabin.h"
#include "rw.h"
#include "asn.h"
#include "rng.h"
#include "files.h"
#include "hex.h"
#include "oids.h"
#include "esign.h"
#include "osrng.h"

#include "md5.h"
#include "ripemd.h"
#include "rng.h"
#include "modes.h"
#include "randpool.h"
#include "ida.h"
#include "base64.h"
#include "factory.h"

#include "regtest.cpp"

#include "bench.h"

#include <iostream>
#include <iomanip>
#include <ctime>
#include <cassert>
#include <chrono>

USING_NAMESPACE(CryptoPP)
USING_NAMESPACE(std)

// The following website contains the mapping of security levels to the appropriate scheme parameters
// http://www.cryptopp.com/wiki/Security_Level
#define NUMBER_OF_SECURITY_LENGTHS 5
int securityLengths[NUMBER_OF_SECURITY_LENGTHS] = {80, 112, 128, 192, 256};
int finiteFieldSizes[NUMBER_OF_SECURITY_LENGTHS] = {1024, 2048, 3072, 7680, 15360};
int finiteFieldSubgroupSizes[NUMBER_OF_SECURITY_LENGTHS] = {160, 224, 256, 384, 511};
int factorizationGroupSizes[NUMBER_OF_SECURITY_LENGTHS] = {1024, 2048, 3072, 7680, 15360};
int ellipticCurveSizes[NUMBER_OF_SECURITY_LENGTHS] = {160, 224, 256, 384, 512};

static OFB_Mode<AES>::Encryption s_globalRNG;

RandomNumberGenerator & GlobalRNG()
{
	return s_globalRNG;
}

string generateDetailedDescription(const string algorithmName, 
	const int securityLevel, const int keyLength) {
	string fullDescription;
	fullDescription.append(algorithmName);
	fullDescription.append(",");
	fullDescription.append(to_string(securityLevel));
	fullDescription.append(",");
	fullDescription.append(to_string(keyLength));
	return fullDescription;
}

string 
generateSignDescription(const string algorithmName, const int securityLevel, const int keyLength) {
	string fullDescription;
	fullDescription.append("sign,");
	fullDescription.append(generateDetailedDescription(algorithmName, securityLevel, keyLength));
	return fullDescription;
}

string 
generateVerifyDescription(const string algorithmName, const int securityLevel, const int keyLength) {
	string fullDescription;
	fullDescription.append("verify,");
	fullDescription.append(generateDetailedDescription(algorithmName, securityLevel, keyLength));
	return fullDescription;
}

string 
generateCSVString(string description, string operation, size_t delta) {
	string csv;
	csv.append(description);
	csv.append(",");
	csv.append(operation);
	csv.append(",");
	csv.append(to_string(delta));
	return csv;
}

class FixedRNG : public RandomNumberGenerator
{
public:
	FixedRNG(BufferedTransformation &source) : m_source(source) {}

	void GenerateBlock(byte *output, size_t size)
	{
		m_source.Get(output, size);
	}

private:
	BufferedTransformation &m_source;
};

bool ProfileSignatureValidate(PK_Signer &priv, PK_Verifier &pub, const byte *input, 
	const size_t inputLength, string description, bool thorough = false)
{
	bool pass = true, fail;

	fail = !pub.GetMaterial().Validate(GlobalRNG(), thorough ? 3 : 2) || !priv.GetMaterial().Validate(GlobalRNG(), thorough ? 3 : 2);
	assert(pass && !fail);

	SecByteBlock signature(priv.MaxSignatureLength());

	std::chrono::steady_clock::time_point signStartTime = std::chrono::steady_clock::now();
	size_t signatureLength = priv.SignMessage(GlobalRNG(), input, inputLength, signature);
	std::chrono::steady_clock::time_point signEndTime = std::chrono::steady_clock::now();
	size_t signNanoSeconds = std::chrono::duration_cast<std::chrono::nanoseconds>(signEndTime - signStartTime).count();

	cout << generateCSVString(description, "sign", signNanoSeconds) << endl;

	std::chrono::steady_clock::time_point verifyStartTime = std::chrono::steady_clock::now();
	fail = !pub.VerifyMessage(input, inputLength, signature, signatureLength);
	std::chrono::steady_clock::time_point verifyEndTime = std::chrono::steady_clock::now();
	size_t verifyNanoSeconds = std::chrono::duration_cast<std::chrono::nanoseconds>(verifyEndTime - verifyStartTime).count();

	cout << generateCSVString(description, "verify", verifyNanoSeconds) << endl;

	assert(pass && !fail);
	return pass;
}

bool ValidateRSA(const byte *input, const size_t inputLength, const int secLevel)
{
	string description = generateDetailedDescription("RSA", secLevel, 1);

	FileSource keys("TestData/rsa512a.dat", true, new HexDecoder);
	Weak::RSASSA_PKCS1v15_MD2_Signer rsaPriv(keys);
	Weak::RSASSA_PKCS1v15_MD2_Verifier rsaPub(rsaPriv);

	bool pass = ProfileSignatureValidate(rsaPriv, rsaPub, input, inputLength, description);
	assert(pass);

	return pass;
}

bool ValidateNR(const byte *input, const size_t inputLength, const int secLevel)
{
	string description = generateDetailedDescription("NR", secLevel, 1);

	bool pass = true;
	{
		FileSource f("TestData/nr2048.dat", true, new HexDecoder);
		NR<SHA>::Signer privS(f);
		privS.AccessKey().Precompute();
		NR<SHA>::Verifier pubS(privS);

		pass = ProfileSignatureValidate(privS, pubS, input, inputLength, description) && pass;
	}
	{
		// cout << "Generating new signature key..." << endl;
		NR<SHA>::Signer privS(GlobalRNG(), 256);
		NR<SHA>::Verifier pubS(privS);

		pass = ProfileSignatureValidate(privS, pubS, input, inputLength, description) && pass;
	}
	return pass;
}

bool ValidateDSA(const byte *input, const size_t inputLength, const int secLevel)
{
	string description = generateDetailedDescription("DSA", secLevel, 1);

	bool pass = true;
	FileSource fs1("TestData/dsa1024.dat", true, new HexDecoder());
	DSA::Signer priv(fs1);
	DSA::Verifier pub(priv);
	FileSource fs2("TestData/dsa1024b.dat", true, new HexDecoder());
	DSA::Verifier pub1(fs2);
	assert(pub.GetKey() == pub1.GetKey());
	pass = ProfileSignatureValidate(priv, pub, input, inputLength, description) && pass;
	return pass;
}

bool ValidateLUC(const byte *input, const size_t inputLength, const int secLevel)
{
	string description = generateDetailedDescription("LUC", secLevel, 1);

	bool pass=true;

	{
		FileSource f("TestData/luc1024.dat", true, new HexDecoder);
		LUCSSA_PKCS1v15_SHA_Signer priv(f);
		LUCSSA_PKCS1v15_SHA_Verifier pub(priv);
		pass = ProfileSignatureValidate(priv, pub, input, inputLength, description) && pass;
	}
	return pass;
}

bool ValidateLUC_DL(const byte *input, const size_t inputLength, const int secLevel)
{
	string description = generateDetailedDescription("LUC-DL", secLevel, 1);

	FileSource f("TestData/lucs512.dat", true, new HexDecoder);
	LUC_HMP<SHA>::Signer privS(f);
	LUC_HMP<SHA>::Verifier pubS(privS);
	bool pass = ProfileSignatureValidate(privS, pubS, input, inputLength, description);

	return pass;
}

bool ValidateRabin(const byte *input, const size_t inputLength, const int secLevel)
{
	string description = generateDetailedDescription("Rabin", secLevel, 1);

	bool pass=true;

	{
		FileSource f("TestData/rabi1024.dat", true, new HexDecoder);
		RabinSS<PSSR, SHA>::Signer priv(f);
		RabinSS<PSSR, SHA>::Verifier pub(priv);
		pass = ProfileSignatureValidate(priv, pub, input, inputLength, description) && pass;
	}

	return pass;
}

bool ValidateRW(const byte *input, const size_t inputLength, const int secLevel)
{
	string description = generateDetailedDescription("RW", secLevel, 1);

	FileSource f("TestData/rw1024.dat", true, new HexDecoder);
	RWSS<PSSR, SHA>::Signer priv(f);
	RWSS<PSSR, SHA>::Verifier pub(priv);

	return ProfileSignatureValidate(priv, pub, input, inputLength, description);
}

bool ValidateECDSA(const byte *input, const size_t inputLength, const int secLevel)
{
	string description = generateDetailedDescription("ECDSA", secLevel, 1);

	// from Sample Test Vectors for P1363
	GF2NT gf2n(191, 9, 0);
	byte a[]="\x28\x66\x53\x7B\x67\x67\x52\x63\x6A\x68\xF5\x65\x54\xE1\x26\x40\x27\x6B\x64\x9E\xF7\x52\x62\x67";
	byte b[]="\x2E\x45\xEF\x57\x1F\x00\x78\x6F\x67\xB0\x08\x1B\x94\x95\xA3\xD9\x54\x62\xF5\xDE\x0A\xA1\x85\xEC";
	EC2N ec(gf2n, PolynomialMod2(a,24), PolynomialMod2(b,24));

	EC2N::Point P;
	ec.DecodePoint(P, (byte *)"\x04\x36\xB3\xDA\xF8\xA2\x32\x06\xF9\xC4\xF2\x99\xD7\xB2\x1A\x9C\x36\x91\x37\xF2\xC8\x4A\xE1\xAA\x0D"
		"\x76\x5B\xE7\x34\x33\xB3\xF9\x5E\x33\x29\x32\xE7\x0E\xA2\x45\xCA\x24\x18\xEA\x0E\xF9\x80\x18\xFB", ec.EncodedPointSize());
	Integer n("40000000000000000000000004a20e90c39067c893bbb9a5H");
	Integer d("340562e1dda332f9d2aec168249b5696ee39d0ed4d03760fH");
	EC2N::Point Q(ec.Multiply(d, P));
	ECDSA<EC2N, SHA>::Signer priv(ec, P, n, d);
	ECDSA<EC2N, SHA>::Verifier pub(priv);

	Integer h("A9993E364706816ABA3E25717850C26C9CD0D89DH");
	Integer k("3eeace72b4919d991738d521879f787cb590aff8189d2b69H");
	byte sig[]="\x03\x8e\x5a\x11\xfb\x55\xe4\xc6\x54\x71\xdc\xd4\x99\x84\x52\xb1\xe0\x2d\x8a\xf7\x09\x9b\xb9\x30"
		"\x0c\x9a\x08\xc3\x44\x68\xc2\x44\xb4\xe5\xd6\xb2\x1b\x3c\x68\x36\x28\x07\x41\x60\x20\x32\x8b\x6e";
	Integer r(sig, 24);
	Integer s(sig+24, 24);

	Integer rOut, sOut;
	bool fail, pass=true;

	priv.RawSign(k, h, rOut, sOut);
	fail = (rOut != r) || (sOut != s);
	pass = pass && !fail;

	assert(pass && !fail);

	fail = !pub.VerifyMessage((byte *)"abc", 3, sig, sizeof(sig));
	pass = pass && !fail;

	assert(pass && !fail);

	fail = pub.VerifyMessage((byte *)"xyz", 3, sig, sizeof(sig));
	pass = pass && !fail;

	pass = ProfileSignatureValidate(priv, pub, input, inputLength, description) && pass;

	return pass;
}

bool ValidateESIGN(const byte *input, const size_t inputLength, const int secLevel)
{
	string description = generateDetailedDescription("ESIGN", secLevel, 1);

	bool pass = true, fail;

	const char *plain = "test";
	const byte *signature = (byte *)
		"\xA3\xE3\x20\x65\xDE\xDA\xE7\xEC\x05\xC1\xBF\xCD\x25\x79\x7D\x99\xCD\xD5\x73\x9D\x9D\xF3\xA4\xAA\x9A\xA4\x5A\xC8\x23\x3D\x0D\x37\xFE\xBC\x76\x3F\xF1\x84\xF6\x59"
		"\x14\x91\x4F\x0C\x34\x1B\xAE\x9A\x5C\x2E\x2E\x38\x08\x78\x77\xCB\xDC\x3C\x7E\xA0\x34\x44\x5B\x0F\x67\xD9\x35\x2A\x79\x47\x1A\x52\x37\x71\xDB\x12\x67\xC1\xB6\xC6"
		"\x66\x73\xB3\x40\x2E\xD6\xF2\x1A\x84\x0A\xB6\x7B\x0F\xEB\x8B\x88\xAB\x33\xDD\xE4\x83\x21\x90\x63\x2D\x51\x2A\xB1\x6F\xAB\xA7\x5C\xFD\x77\x99\xF2\xE1\xEF\x67\x1A"
		"\x74\x02\x37\x0E\xED\x0A\x06\xAD\xF4\x15\x65\xB8\xE1\xD1\x45\xAE\x39\x19\xB4\xFF\x5D\xF1\x45\x7B\xE0\xFE\x72\xED\x11\x92\x8F\x61\x41\x4F\x02\x00\xF2\x76\x6F\x7C"
		"\x79\xA2\xE5\x52\x20\x5D\x97\x5E\xFE\x39\xAE\x21\x10\xFB\x35\xF4\x80\x81\x41\x13\xDD\xE8\x5F\xCA\x1E\x4F\xF8\x9B\xB2\x68\xFB\x28";

	FileSource keys("TestData/esig1536.dat", true, new HexDecoder);
	ESIGN<SHA>::Signer signer(keys);
	ESIGN<SHA>::Verifier verifier(signer);

	fail = !ProfileSignatureValidate(signer, verifier, input, inputLength, description);
	pass = pass && !fail;

	fail = !verifier.VerifyMessage((byte *)plain, strlen(plain), signature, verifier.SignatureLength());
	pass = pass && !fail;

	assert(pass && !fail);

	// cout << "Generating signature key from seed..." << endl;
	signer.AccessKey().GenerateRandom(GlobalRNG(), MakeParameters("Seed", ConstByteArrayParameter((const byte *)"test", 4))("KeySize", 3*512));
	verifier = signer;

	fail = !ProfileSignatureValidate(signer, verifier, input, inputLength, description);
	pass = pass && !fail;

	return pass;
}

void ProfileSignatureSchemes(const byte *inputData, const size_t inputLength, const int securityLevel) {
	ValidateRSA(inputData, inputLength, securityLevel);
	ValidateNR(inputData, inputLength, securityLevel);
	ValidateDSA(inputData, inputLength, securityLevel);
	ValidateLUC(inputData, inputLength, securityLevel);
	ValidateLUC_DL(inputData, inputLength, securityLevel);
	ValidateRabin(inputData, inputLength, securityLevel);
	ValidateRW(inputData, inputLength, securityLevel);
	ValidateECDSA(inputData, inputLength, securityLevel);
	ValidateESIGN(inputData, inputLength, securityLevel);
}

void showUsage() {
	cout << "usage: verifier <security-level> <rng-seed>" << endl;
	cout << "       security-level: the AES security equivalent level" << endl;
	cout << "       rng-seed:       the seed for the global RNG" << endl;
}

int main(int argc, char **argv) {

	if (argc != 3) {
		showUsage();
		return -1;
	}

	int securityLevel = atoi(argv[1]);
	string rngSeed(argv[2]);
	size_t rngSeedLength = 16;

	string fullLine;
	string line;
	while (getline(cin, line)) {
		fullLine.append(line);
	}
	byte *inputData = (byte *) fullLine.data();
	int inputLength = fullLine.length();

	RegisterFactories();
	rngSeed.resize(rngSeedLength);
	s_globalRNG.SetKeyWithIV((byte *)rngSeed.data(), rngSeedLength, (byte *)rngSeed.data());
	
	// TODO: plug in all the other verification algorithms here
	ProfileSignatureSchemes(inputData, inputLength, securityLevel);
}
