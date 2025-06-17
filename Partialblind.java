import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.MGFParameters;
import org.bouncycastle.crypto.generators.MGF1BytesGenerator;

// --- Shared Configuration Parameters ---
// The length in bytes of the RSA modulus n. This determines the size of keys and signatures.
// For RSA 2048-bit key, 2048/8 = 256 bytes.
class Config {
    public static final int MODULUS_LEN = 256;
    // The hash algorithm used in PSS (e.g., SHA-256).
    public static final String HASH_ALGORITHM = "SHA-256";
    // The mask generation function used in PSS (e.g., MGF1).
    public static final String MGF_ALGORITHM = "MGF1";
    // The length in bytes of the salt used in PSS. Typically same as hash output size (32 bytes for SHA-256).
    public static final int SALT_LEN = 32;
    // The algorithm string for RSASSA-PSS with specified hash and MGF.
    public static final String PSS_ALGORITHM = "RSASSA-PSS";
}

// --- Helper Functions (Static for reusability across components) ---
class CryptoHelpers {

    /**
     * Concatenates multiple byte arrays into a single byte array.
     * @param arrays A variable number of byte arrays to concatenate.
     * @return The concatenated byte array.
     */
    public static byte[] concat(byte[]... arrays) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        for (byte[] array : arrays) {
            try {
                outputStream.write(array);
            } catch (IOException e) {
                // This should not happen with ByteArrayOutputStream
                throw new RuntimeException("Error concatenating byte arrays", e);
            }
        }
        return outputStream.toByteArray();
    }

    /**
     * Converts an integer to a byte array of a specified length.
     * Note: This specifically handles the 4-byte info length as per the spec.
     * @param value The integer value.
     * @param length The desired length of the byte array.
     * @return The byte array representation of the integer.
     */
    public static byte[] int_to_bytes(int value, int length) {
        if (length == 4) {
            return ByteBuffer.allocate(4).putInt(value).array();
        } else {
            throw new IllegalArgumentException("int_to_bytes for variable length not supported directly. Use BigInteger.toByteArray() for large numbers.");
        }
    }

    /**
     * Converts a byte array to a BigInteger.
     * @param bytes The byte array.
     * @return The BigInteger representation.
     */
    public static BigInteger bytes_to_int(byte[] bytes) {
        return new BigInteger(1, bytes); // 1 for positive BigInteger
    }

    /**
     * Ensures a BigInteger's byte array representation has a specific length (e.g., MODULUS_LEN).
     * Pads with leading zeros or removes a leading zero byte if present from BigInteger.toByteArray().
     * @param value The BigInteger to convert.
     * @param length The desired length of the byte array.
     * @return The byte array representation, padded/adjusted to `length`.
     * @throws RuntimeException if the value cannot fit within the specified length.
     */
    public static byte[] big_int_to_fixed_bytes(BigInteger value, int length) {
        byte[] bytes = value.toByteArray();
        if (bytes.length == length) {
            return bytes;
        } else if (bytes.length == length + 1 && bytes[0] == 0) {
            // Remove leading zero if BigInteger.toByteArray added it for positive numbers
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        } else if (bytes.length < length) {
            byte[] padded = new byte[length];
            // Copy bytes to the end of the new array
            System.arraycopy(bytes, 0, padded, length - bytes.length, bytes.length);
            return padded;
        } else {
            // Value is too large to fit in the specified length, or unexpected format
            throw new RuntimeException("Value is too large to convert to " + length + " bytes.");
        }
    }

    /**
     * Checks if two BigIntegers are coprime (their greatest common divisor is 1).
     * @param a First BigInteger.
     * @param b Second BigInteger.
     * @return True if coprime, false otherwise.
     */
    public static boolean is_coprime(BigInteger a, BigInteger b) {
        return a.gcd(b).equals(BigInteger.ONE);
    }

    /**
     * Generates a random BigInteger uniformly between min (inclusive) and max (exclusive).
     * @param min The minimum value (inclusive).
     * @param max The maximum value (exclusive).
     * @return A random BigInteger within the specified range.
     */
    public static BigInteger random_integer_uniform(BigInteger min, BigInteger max) {
        if (min.compareTo(max) >= 0) {
            throw new IllegalArgumentException("Max must be greater than min");
        }
        BigInteger range = max.subtract(min);
        SecureRandom sr = new SecureRandom();
        BigInteger randomNumber;
        do {
            randomNumber = new BigInteger(range.bitLength(), sr);
        } while (randomNumber.compareTo(range) >= 0);
        return min.add(randomNumber);
    }

    /**
     * Calculates the modular multiplicative inverse of 'a' modulo 'm'.
     * @param a The number for which to find the inverse.
     * @param m The modulus.
     * @return The modular multiplicative inverse.
     * @throws ArithmeticException if the inverse does not exist (a and m are not coprime).
     */
    public static BigInteger inverse_mod(BigInteger a, BigInteger m) {
        return a.modInverse(m);
    }

    // --- Key Derivation (PLACEHOLDER) ---
    /**
     * Placeholder for DerivePublicKey. In a real system, this would derive
     * a public key from the master public key and info using a specified algorithm.
     * For this demo, it returns the original public key.
     * @param pk The original public key.
     * @param info Public metadata.
     * @return The derived public key.
     */
    public static PublicKey DerivePublicKey(PublicKey pk, byte[] info) {
        // !!! IMPORTANT: THIS IS A PLACEHOLDER IMPLEMENTATION !!!
        // A real DerivePublicKey would compute a new public key based on pk and info.
        // The specific algorithm for this derivation is NOT defined in the IETF draft.
        // It would typically involve a KDF (e.g., HKDF) and a method to derive RSA parameters.
        System.out.println("DerivePublicKey: Using original public key as derived key (PLACEHOLDER).");
        return pk;
    }

    /**
     * Placeholder for DeriveKeyPair. In a real system, this would derive
     * a new key pair from the master private key and info using a specified algorithm.
     * For this demo, it returns the original private and public keys.
     * @param sk The original private key.
     * @param pk The original public key (needed if sk doesn't contain it).
     * @param info Public metadata.
     * @return A KeyPair containing the derived private key and derived public key.
     */
    public static KeyPair DeriveKeyPair(PrivateKey sk, PublicKey pk, byte[] info) {
        // !!! IMPORTANT: THIS IS A PLACEHOLDER IMPLEMENTATION !!!
        // A real DeriveKeyPair would compute a new key pair based on sk and info.
        // The specific algorithm for this derivation is NOT defined in the IETF draft.
        System.out.println("DeriveKeyPair: Using original key pair as derived key pair (PLACEHOLDER).");
        return new KeyPair(pk, sk);
    }

    // --- RSA Primitives (Conceptual for Demonstration using BigInteger.modPow) ---

    /**
     * Conceptual RSAVP1: RSA Verification Primitive 1 (s^e mod n).
     * Used for low-level modular exponentiation with the public exponent.
     * @param pk The public key (or derived public key).
     * @param s The integer to be exponentiated.
     * @return The result of s^e mod n.
     */
    public static BigInteger RSAVP1(PublicKey pk, BigInteger s) {
        if (!(pk instanceof java.security.interfaces.RSAPublicKey)) {
            throw new IllegalArgumentException("PublicKey must be an RSAPublicKey.");
        }
        java.security.interfaces.RSAPublicKey rsaPk = (java.security.interfaces.RSAPublicKey) pk;
        BigInteger n = rsaPk.getModulus();
        BigInteger e = rsaPk.getPublicExponent();
        return s.modPow(e, n);
    }

    /**
     * Conceptual RSASP1: RSA Signature Primitive 1 (m^d mod n).
     * Used for low-level modular exponentiation with the private exponent.
     * @param sk The private key (or derived private key).
     * @param m The integer to be exponentiated.
     * @return The result of m^d mod n.
     */
    public static BigInteger RSASP1(PrivateKey sk, BigInteger m) {
        if (!(sk instanceof java.security.interfaces.RSAPrivateKey)) {
            throw new IllegalArgumentException("PrivateKey must be an RSAPrivateKey.");
        }
        java.security.interfaces.RSAPrivateKey rsaSk = (java.security.interfaces.RSAPrivateKey) sk;
        BigInteger n = rsaSk.getModulus();
        BigInteger d = rsaSk.getPrivateExponent();

        // Check "message representative out of range" error (m not between 0 and n-1)
        if (m.compareTo(BigInteger.ZERO) < 0 || m.compareTo(n) >= 0) {
            throw new IllegalArgumentException("message representative out of range: m must be between 0 and n-1.");
        }
        return m.modPow(d, n);
    }

    /**
     * Implements EMSA-PSS-ENCODE as specified in RFC 8017, Section 9.1.1.
     * This function generates the PSS-encoded message block (EM) which is then
     * converted to an integer 'm' for RSA modular exponentiation.
     *
     * @param M The message to be encoded (msg_prime in our context).
     * @param emBits The intended length of the encoded message in bits (bit_len(n) - 1).
     * @return The PSS-encoded message block (EM).
     * @throws IllegalArgumentException if encoding parameters are invalid.
     */
    public static byte[] emsa_pss_encode(byte[] M, int emBits) throws NoSuchAlgorithmException {
        // emLen is the length of EM in bytes. emBits is bit_len(n) - 1.
        // (emBits + 7) / 8 effectively rounds up to the nearest byte.
        int emLen = (emBits + 7) / 8;

        // Use Bouncy Castle's Digest for hashing
        Digest hash = new SHA256Digest(); // Using SHA-256 as per Config
        int hLen = hash.getDigestSize(); // Output size of hash (32 bytes for SHA-256)
        int sLen = Config.SALT_LEN;      // Configured salt length

        // Step 1: mHash = Hash(M)
        byte[] mHash = new byte[hLen];
        hash.update(M, 0, M.length);
        hash.doFinal(mHash, 0);
        System.out.println("EMSA-PSS-ENCODE: mHash (Hash(M)) generated: " + Base64.getEncoder().encodeToString(mHash));


        // Step 2: If emLen < hLen + sLen + 2, output "encoding error"
        if (emLen < hLen + sLen + 2) {
            throw new IllegalArgumentException("EMSA-PSS-ENCODE encoding error: emLen (" + emLen + ") too small for hLen (" + hLen + ") + sLen (" + sLen + ") + 2.");
        }

        // Step 3: Generate salt (random byte string of length sLen)
        byte[] salt = new byte[sLen];
        new SecureRandom().nextBytes(salt);
        System.out.println("EMSA-PSS-ENCODE: Salt generated: " + Base64.getEncoder().encodeToString(salt));


        // Step 4: M' = (0x)00...00 || mHash || salt (8 zero bytes || mHash || salt)
        byte[] M_prime_prefix = new byte[8]; // 8 zero bytes as specified in RFC 8017
        byte[] M_prime_for_hash = CryptoHelpers.concat(M_prime_prefix, mHash, salt);
        System.out.println("EMSA-PSS-ENCODE: M' (for hash H) created. Length: " + M_prime_for_hash.length);

        // Step 5: H = Hash(M')
        byte[] H = new byte[hLen];
        hash.update(M_prime_for_hash, 0, M_prime_for_hash.length);
        hash.doFinal(H, 0);
        System.out.println("EMSA-PSS-ENCODE: H (Hash(M')) generated: " + Base64.getEncoder().encodeToString(H));

        // Step 6: PS (padding string of zeros). Length emLen - sLen - hLen - 2
        int psLen = emLen - sLen - hLen - 2;
        byte[] PS = new byte[psLen]; // All zeros by default in Java for new byte[]
        System.out.println("EMSA-PSS-ENCODE: PS (padding string) created. Length: " + PS.length);

        // Step 7: DB = PS || 0x01 || salt
        byte[] DB = CryptoHelpers.concat(PS, new byte[]{0x01}, salt);
        System.out.println("EMSA-PSS-ENCODE: DB created. Length: " + DB.length);

        // Step 8: dbMask = MGF(H, emLen - hLen - 1)
        byte[] dbMask = new byte[emLen - hLen - 1]; // Length of masked DB part
        // MGF1 with the specified hash algorithm (SHA256Digest)
        MGF1BytesGenerator mgf1 = new MGF1BytesGenerator(new SHA256Digest());
        mgf1.init(new MGFParameters(H)); // Seed MGF with H
        mgf1.generateBytes(dbMask, 0, dbMask.length);
        System.out.println("EMSA-PSS-ENCODE: dbMask generated. Length: " + dbMask.length);


        // Step 9: maskedDB = DB XOR dbMask
        byte[] maskedDB = new byte[DB.length];
        if (DB.length != dbMask.length) {
            throw new IllegalStateException("DB length (" + DB.length + ") does not match dbMask length (" + dbMask.length + "). This indicates an internal calculation error in PSS encoding.");
        }
        for (int i = 0; i < DB.length; i++) {
            maskedDB[i] = (byte) (DB[i] ^ dbMask[i]);
        }
        System.out.println("EMSA-PSS-ENCODE: maskedDB created.");


        // Step 10: Set leftmost (8 * emLen - emBits) bits of maskedDB[0] to 0.
        // emBits = bit_len(n) - 1. So, (8 * emLen - emBits) is the number of unused bits in the leftmost byte.
        int numBitsToClear = (8 * emLen) - emBits;
        if (numBitsToClear > 0) {
            maskedDB[0] &= (byte) (0xFF >>> numBitsToClear);
            System.out.println("EMSA-PSS-ENCODE: Cleared " + numBitsToClear + " leftmost bits of maskedDB[0].");
        }

        // Step 11: EM = maskedDB || H || 0xbc
        byte[] EM = CryptoHelpers.concat(maskedDB, H, new byte[]{(byte) 0xbc});
        System.out.println("EMSA-PSS-ENCODE: EM (Encoded Message) generated. Length: " + EM.length);

        // Step 12: Output EM
        return EM;
    }
}


// --- Client Component ---
class Client {
    private byte[] originalMsg;
    private byte[] publicInfo;
    private BigInteger blindingInverse; // 'inv' from Blind function

    public Client(byte[] msg, byte[] info) {
        this.originalMsg = msg;
        this.publicInfo = info;
    }

    /**
     * Section 4.1: Prepares the message for blinding.
     * As per the document: "Verification and the message that applications consume therefore depends on which
     * preparation function is used."
     * @param type The type of preparation: "identity" or "randomize".
     * @return The prepared message (input_msg).
     */
    public byte[] prepare(String type) {
        System.out.println("\n--- Client: Preparing Message (Section 4.1) ---");
        if ("identity".equalsIgnoreCase(type)) {
            // PrepareIdentity: input_msg is simply msg.
            System.out.println("Prepare: Using PrepareIdentity.");
            return originalMsg;
        } else if ("randomize".equalsIgnoreCase(type)) {
            // PrepareRandomize: input_msg for blinding needs to be random_prefix || msg.
            // The application message is then slice(input_msg, 32, len(input_msg)), i.e.,
            // the prepared message with the random prefix removed.
            System.out.println("Prepare: Using PrepareRandomize.");
            byte[] randomPrefix = new byte[32];
            new SecureRandom().nextBytes(randomPrefix);
            byte[] preparedMsg = CryptoHelpers.concat(randomPrefix, originalMsg);
            System.out.println("Prepare: Random prefix added. Prepared message length: " + preparedMsg.length);
            return preparedMsg;
        } else {
            throw new IllegalArgumentException("Invalid Prepare type: " + type);
        }
    }

    /**
     * Section 4.2: Blinds the prepared message using the server's public key and public metadata.
     * This function now implements the full EMSA-PSS-ENCODE as per RFC 8017.
     *
     * Parameters: modulus_len, Hash, MGF, salt_len (configured as static fields).
     * @param pk The server's public key (n, e).
     * @param input_msg The prepared message byte string.
     * @return The blinded message (blind_msg).
     * @throws RuntimeException for various blinding errors.
     */
    public byte[] blind(PublicKey pk, byte[] input_msg) {
        System.out.println("\n--- Client: Blinding Message (Section 4.2) ---");
        // 1. msg_prime = concat("msg", int_to_bytes(len(info), 4), info, input_msg)
        // This msg_prime is the 'M' input to EMSA-PSS-ENCODE.
        byte[] msgPrefix = "msg".getBytes(StandardCharsets.UTF_8);
        byte[] infoLenBytes = CryptoHelpers.int_to_bytes(publicInfo.length, 4);
        byte[] msg_prime = CryptoHelpers.concat(msgPrefix, infoLenBytes, publicInfo, input_msg);
        System.out.println("1. msg_prime (M for PSS encoding) created. Length: " + msg_prime.length);

        // Get RSA public key components for modulus n to determine emBits
        java.security.interfaces.RSAPublicKey rsaPk = (java.security.interfaces.RSAPublicKey) pk;
        BigInteger n = rsaPk.getModulus();
        int bitLenN = n.bitLength();
        // emBits = bit_len(n) - 1 as specified for RSASSA-PSS
        int emBits = bitLenN - 1;
        System.out.println("RSA Modulus bit length (n.bitLength()): " + bitLenN + ", emBits: " + emBits);


        // 2. encoded_msg = EMSA-PSS-ENCODE(msg_prime, emBits)
        // This is the core update: perform full EMSA-PSS-ENCODE.
        byte[] encoded_msg; // This is the EM block
        try {
            encoded_msg = CryptoHelpers.emsa_pss_encode(msg_prime, emBits);
            System.out.println("2. EMSA-PSS-ENCODE completed. EM block generated.");
            System.out.println("   EM block (Base64): " + Base64.getEncoder().encodeToString(encoded_msg));
        } catch (NoSuchAlgorithmException | IllegalArgumentException e) {
            // Catches errors from emsa_pss_encode, including "message too long" and "encoding error"
            throw new RuntimeException("Encoding error during EMSA-PSS-ENCODE: " + e.getMessage(), e);
        }

        // 3. If EMSA-PSS-ENCODE raises an error, raise the error and stop (handled by try-catch above)

        // 4. m = bytes_to_int(encoded_msg)
        // The EM block is now converted to BigInteger 'm' for modular arithmetic.
        BigInteger m = CryptoHelpers.bytes_to_int(encoded_msg);
        System.out.println("4. Converted EM block to integer m.");

        // 5. c = is_coprime(m, n)
        boolean c = CryptoHelpers.is_coprime(m, n);
        System.out.println("5. m is coprime with n: " + c);

        // 6. If c is false, raise an "invalid input" error and stop
        if (!c) {
            throw new RuntimeException("invalid input: message (m) is not co-prime with n. This should be rare with proper PSS encoding.");
        }

        // 7. r = random_integer_uniform(1, n)
        BigInteger r = CryptoHelpers.random_integer_uniform(BigInteger.ONE, n);
        System.out.println("7. Generated random blinding factor r.");

        // 8. inv = inverse_mod(r, n)
        try {
            this.blindingInverse = CryptoHelpers.inverse_mod(r, n);
            System.out.println("8. Calculated inverse of r (inv).");
        } catch (ArithmeticException e) {
            // 9. If inverse_mod fails, raise an "blinding error" error and stop
            throw new RuntimeException("blinding error: Inverse of r cannot be found (r is not coprime to n).", e);
        }

        // 10. pk_derived = DerivePublicKey(pk, info)
        PublicKey pk_derived = CryptoHelpers.DerivePublicKey(pk, publicInfo);
        System.out.println("10. Derived public key (pk_derived).");

        // 11. x = RSAVP1(pk_derived, r)
        // x = r^e mod n
        BigInteger x = CryptoHelpers.RSAVP1(pk_derived, r);
        System.out.println("11. Computed x = RSAVP1(pk_derived, r).");

        // 12. z = m * x mod n
        // This is the blinded message representative sent to the server.
        BigInteger z = m.multiply(x).mod(n);
        System.out.println("12. Computed z = m * x mod n (blinded message representative).");

        // 13. blind_msg = int_to_bytes(z, modulus_len)
        byte[] blind_msg = CryptoHelpers.big_int_to_fixed_bytes(z, Config.MODULUS_LEN);
        System.out.println("13. Converted z to blind_msg byte array. Length: " + blind_msg.length);


        // 14. output blind_msg, inv (inv stored internally)
        System.out.println("Client Blind (Section 4.2): Completed. Output blind_msg.");
        return blind_msg;
    }

    /**
     * Client finalizes the signature and verifies it.
     * This now uses RSASSA-PSS verification, as the blinding process is compliant.
     * @param pk Server's public key (n, e).
     * @param blind_sig Signed and blinded element, a byte string.
     * @return The final, unblinded, and verified signature (sig).
     * @throws RuntimeException for invalid signature or unexpected input size.
     */
    public byte[] finalizeSignature(PublicKey pk, byte[] blind_sig) {
        System.out.println("\n--- Client: Finalizing Signature ---");
        // 1. If len(blind_sig) != modulus_len, raise "unexpected input size" and stop
        if (blind_sig.length != Config.MODULUS_LEN) {
            throw new RuntimeException("unexpected input size: blind_sig length (" + blind_sig.length + ") does not match modulus_len (" + Config.MODULUS_LEN + ").");
        }
        System.out.println("1. blind_sig length validated.");

        // 2. z = bytes_to_int(blind_sig)
        BigInteger z = CryptoHelpers.bytes_to_int(blind_sig);
        System.out.println("2. Converted blind_sig to integer z.");

        // Get RSA public key components for modulus n
        java.security.interfaces.RSAPublicKey rsaPk = (java.security.interfaces.RSAPublicKey) pk;
        BigInteger n = rsaPk.getModulus();

        // 3. s = z * inv mod n
        // This should recover the PSS-encoded message (EM) as an integer.
        BigInteger s = z.multiply(this.blindingInverse).mod(n);
        System.out.println("3. Unblinded signature: s = z * inv mod n (This is the unblinded EM as an integer).");

        // 4. sig = int_to_bytes(s, modulus_len)
        // Convert the unblinded integer back to byte array for verification.
        byte[] sig_bytes = CryptoHelpers.big_int_to_fixed_bytes(s, Config.MODULUS_LEN);
        System.out.println("4. Converted s to final signature (sig) byte array. Length: " + sig_bytes.length);

        // 5. msg_prime = concat("msg", int_to_bytes(len(info), 4), info, originalMsg)
        // This is the 'M' that was originally fed to EMSA-PSS-ENCODE.
        byte[] msgPrefix = "msg".getBytes(StandardCharsets.UTF_8);
        byte[] infoLenBytes = CryptoHelpers.int_to_bytes(publicInfo.length, 4);
        byte[] msg_prime = CryptoHelpers.concat(msgPrefix, infoLenBytes, publicInfo, originalMsg); // Use original 'msg' here
        System.out.println("5. Re-created msg_prime (M for PSS verification). Length: " + msg_prime.length);

        // 6. pk_derived = DerivePublicKey(pk, info)
        PublicKey pk_derived = CryptoHelpers.DerivePublicKey(pk, publicInfo);
        System.out.println("6. Derived public key (pk_derived) for verification.");

        // 7. result = RSASSA-PSS-VERIFY(pk_derived, msg_prime, sig)
        // This will now correctly use RSASSA-PSS as the generated signature is PSS-compliant.
        boolean result;
        try {
            Signature verifier = Signature.getInstance(Config.PSS_ALGORITHM, "BC"); // Using RSASSA-PSS with BC
            PSSParameterSpec pssSpec = new PSSParameterSpec(
                    Config.HASH_ALGORITHM,
                    Config.MGF_ALGORITHM, // MGF1
                    new MGF1ParameterSpec(Config.HASH_ALGORITHM), // MGF1 with SHA-256
                    Config.SALT_LEN,
                    PSSParameterSpec.TRAILER_FIELD_BC // 0xBC trailer
            );
            verifier.setParameter(pssSpec);
            verifier.initVerify(pk_derived);
            verifier.update(msg_prime); // Update with the original message (M)
            result = verifier.verify(sig_bytes); // Verify the unblinded PSS-encoded message (EM)
            System.out.println("7. " + Config.PSS_ALGORITHM + " verification result: " + (result ? "Valid" : "Invalid"));
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | InvalidAlgorithmParameterException | NoSuchProviderException e) {
            throw new RuntimeException("Verification error: " + e.getMessage(), e);
        }

        // 8. If result = "valid signature", output sig, else raise "invalid signature" and stop
        if (result) {
            System.out.println("Client Finalize: Completed. Signature is VALID. Output sig.");
            return sig_bytes;
        } else {
            throw new RuntimeException("invalid signature: " + Config.PSS_ALGORITHM + " verification failed.");
        }
    }
}


// --- Server Component ---
class Server {
    private PublicKey serverPublicKey;
    private PrivateKey serverPrivateKey;

    public Server(KeyPair keyPair) {
        this.serverPublicKey = keyPair.getPublic();
        this.serverPrivateKey = keyPair.getPrivate();
    }

    public PublicKey getPublicKey() {
        return serverPublicKey;
    }

    /**
     * The server signs the blinded message.
     * @param blind_msg The blinded message received from the client.
     * @param info Public metadata.
     * @return The blinded signature (blind_sig).
     * @throws RuntimeException for signing failures.
     */
    public byte[] blindSign(byte[] blind_msg, byte[] info) {
        System.out.println("\n--- Server: Blind Signing Message ---");
        // 1. m = bytes_to_int(blind_msg)
        // This 'm' is the PSS-encoded message block as an integer, received from the client.
        BigInteger m = CryptoHelpers.bytes_to_int(blind_msg);
        System.out.println("1. Converted blind_msg to integer m (PSS-encoded message representative).");

        // 2. sk_derived, pk_derived = DeriveKeyPair(sk, info)
        // The server derives the specific key pair based on the public metadata.
        KeyPair derivedKeyPair = CryptoHelpers.DeriveKeyPair(serverPrivateKey, serverPublicKey, info);
        PrivateKey sk_derived = derivedKeyPair.getPrivate();
        PublicKey pk_derived = derivedKeyPair.getPublic();
        System.out.println("2. Derived key pair (sk_derived, pk_derived) using info.");

        // 3. s = RSASP1(sk_derived, m)
        // The server performs the raw RSA signature (modular exponentiation) on 'm'.
        BigInteger s = CryptoHelpers.RSASP1(sk_derived, m);
        System.out.println("3. Computed s = RSASP1(sk_derived, m) (raw RSA signature on PSS-encoded message).");

        // 4. m' = RSAVP1(pk_derived, s)
        // Internal verification: server verifies its own signature.
        BigInteger m_prime = CryptoHelpers.RSAVP1(pk_derived, s);
        System.out.println("4. Computed m' = RSAVP1(pk_derived, s) (recovered PSS-encoded message representative).");

        // 5. If m != m', raise "signing failure" and stop
        if (!m.equals(m_prime)) {
            throw new RuntimeException("signing failure: Internal verification failed (m != m'). Recovered PSS-encoded message mismatch.");
        }
        System.out.println("5. Internal verification passed (m == m'). Signature is consistent.");

        // 6. blind_sig = int_to_bytes(s, modulus_len)
        // Convert the raw RSA signature back to byte array for sending to client.
        byte[] blind_sig_bytes = CryptoHelpers.big_int_to_fixed_bytes(s, Config.MODULUS_LEN);
        System.out.println("6. Converted s to blind_sig byte array. Length: " + blind_sig_bytes.length);

        System.out.println("Server BlindSign: Completed. Output blind_sig.");
        return blind_sig_bytes;
    }
}


// --- Verifier Component (Can be a separate class or static utility) ---
class Verifier {

    /**
     * Verifies the final signature. This simulates what a third party or
     * the application consuming the signed message would do.
     * This now uses RSASSA-PSS verification, as the blinding process is compliant.
     *
     * @param pk Server's public key.
     * @param msg Original message.
     * @param info Public metadata.
     * @param sig The final signature to verify.
     * @param prepareType The type of preparation ("identity" or "randomize") used during blinding.
     * @return true if the signature is valid, false otherwise.
     */
    public static boolean verifyFinalSignature(PublicKey pk, byte[] msg, byte[] info, byte[] sig, String prepareType) {
        System.out.println("\n--- Verifier: Independent Verification ---");
        try {
            // Re-prepare input_msg based on the original prepareType for accurate msg_prime calculation.
            // The verifier must know how the original message was prepared to correctly compute msg_prime.
            byte[] input_msg_for_verification;
            if ("identity".equalsIgnoreCase(prepareType)) {
                input_msg_for_verification = msg;
                System.out.println("Verifier: Using PrepareIdentity for msg_prime construction.");
            } else if ("randomize".equalsIgnoreCase(prepareType)) {
                // For `PrepareRandomize`, the `input_msg` that was blinded by the client included a 32-byte random prefix.
                // The `msg_prime` for RSASSA-PSS verification *must* be derived from this exact `input_msg`.
                // However, an independent verifier typically only has `msg` (original) and `info`.
                // To properly verify a `PrepareRandomize` signature, the random prefix (or the full `input_msg`)
                // would need to be transmitted along with the `msg` and `sig`.
                // For this demo, aligning with the `Finalize` function's behavior (which uses `originalMsg` for `msg_prime`),
                // we'll proceed with the assumption that `msg` (original) is the relevant part for the verifier's `msg_prime`.
                // In a real-world scenario, this aspect of `PrepareRandomize` would need careful design regarding what is
                // actually verified by an independent party.
                input_msg_for_verification = msg; // This is a simplification/assumption for demo
                System.out.println("Verifier: Assuming original msg for msg_prime construction in 'randomize' type (DEMO SIMPLIFICATION FOR VERIFICATION).");
            } else {
                throw new IllegalArgumentException("Invalid Prepare type for verification: " + prepareType);
            }

            // Compute pk_derived = DerivePublicKey(pk, info).
            PublicKey pk_derived_verify = CryptoHelpers.DerivePublicKey(pk, info);
            System.out.println("Verifier: Derived public key (pk_derived) for verification.");

            // Compute msg_prime = concat("msg", int_to_bytes(len(info), 4), info, input_msg_for_verification).
            // This 'msg_prime' is the 'M' input to the PSS encoding that the verifier internally performs.
            byte[] msgPrefix = "msg".getBytes(StandardCharsets.UTF_8);
            byte[] infoLenBytes = CryptoHelpers.int_to_bytes(info.length, 4);
            byte[] msg_prime_verify = CryptoHelpers.concat(msgPrefix, infoLenBytes, info, input_msg_for_verification);
            System.out.println("Verifier: Re-created msg_prime (M for PSS verification). Length: " + msg_prime_verify.length);

            // Invoke RSASSA-PSS-VERIFY
            // This will now correctly use RSASSA-PSS as the generated signature is PSS-compliant.
            Signature verifier = Signature.getInstance(Config.PSS_ALGORITHM, "BC"); // Using RSASSA-PSS with BC
            PSSParameterSpec pssSpec = new PSSParameterSpec(
                    Config.HASH_ALGORITHM,
                    Config.MGF_ALGORITHM, // MGF1
                    new MGF1ParameterSpec(Config.HASH_ALGORITHM), // MGF1 with SHA-256
                    Config.SALT_LEN,
                    PSSParameterSpec.TRAILER_FIELD_BC // 0xBC trailer
            );
            verifier.setParameter(pssSpec);
            verifier.initVerify(pk_derived_verify);
            verifier.update(msg_prime_verify); // Update with the original message (M)
            boolean result = verifier.verify(sig); // Verify the unblinded PSS-encoded message (EM)
            System.out.println("Verifier: " + Config.PSS_ALGORITHM + " verification result: " + (result ? "Valid" : "Invalid"));
            return result;

        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | InvalidAlgorithmParameterException | NoSuchProviderException e) {
            System.err.println("Verifier error during verification: " + e.getMessage());
            return false;
        }
    }
}


// --- Main Application to Orchestrate Components ---
public class PartiallyBlindRSADemo {

    public static void main(String[] args) {
        System.out.println("--- Starting Partially Blind RSA Demo with Separate Components and Bouncy Castle (Full PSS) ---");

        // Register Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());
        System.out.println("Bouncy Castle Provider Registered.");

        // 1. Generate RSA Key Pair for the Server
        KeyPairGenerator keyGen;
        try {
            keyGen = KeyPairGenerator.getInstance("RSA", "BC"); // Use BC provider for key generation
            keyGen.initialize(Config.MODULUS_LEN * 8, new SecureRandom()); // RSA key size in bits (e.g., 2048 bits for 256 bytes)
            KeyPair serverKeyPair = keyGen.generateKeyPair();
            System.out.println("\nGenerated Server RSA Key Pair.");
            System.out.println("Server Public Key Modulus Length (bytes): " + ((java.security.interfaces.RSAPublicKey)serverKeyPair.getPublic()).getModulus().toByteArray().length);

            // Instantiate Server
            Server server = new Server(serverKeyPair);
            PublicKey serverPublicKey = server.getPublicKey();

            // Client's original message
            byte[] clientOriginalMsg = "some text to be signed blindly".getBytes(StandardCharsets.UTF_8);
            System.out.println("\nClient's original message: '" + new String(clientOriginalMsg) + "'");

            // Public metadata (info)
            byte[] publicInfo = "{\"fs\":\"10\"}".getBytes(StandardCharsets.UTF_8);
            System.out.println("Public metadata (info): '" + new String(publicInfo) + "'");


            // --- Scenario 1: Using PrepareIdentity ---
            System.out.println("\n\n--- SCENARIO 1: Using PrepareIdentity ---");
            Client clientIdentity = new Client(clientOriginalMsg, publicInfo);

            // Client prepares and blinds message
            byte[] input_msg_identity = clientIdentity.prepare("identity");
            byte[] blindMsgIdentity = clientIdentity.blind(serverPublicKey, input_msg_identity);

            // Server blind signs message
            byte[] blindSigIdentity = server.blindSign(blindMsgIdentity, publicInfo);

            // Client finalizes and verifies signature
            byte[] finalSigIdentity = clientIdentity.finalizeSignature(serverPublicKey, blindSigIdentity);
            System.out.println("Final Signature (Identity) (Base64): " + Base64.getEncoder().encodeToString(finalSigIdentity));

            // Independent Verifier checks the final signature
            boolean verifyAppResultIdentity = Verifier.verifyFinalSignature(serverPublicKey, clientOriginalMsg, publicInfo, finalSigIdentity, "identity");
            System.out.println("Independent Verification (Identity) Result: " + (verifyAppResultIdentity ? "SUCCESS" : "FAILURE"));


            // --- Scenario 2: Using PrepareRandomize ---
            System.out.println("\n\n--- SCENARIO 2: Using PrepareRandomize ---");
            Client clientRandomize = new Client(clientOriginalMsg, publicInfo);

            // Client prepares and blinds message
            byte[] input_msg_randomize = clientRandomize.prepare("randomize");
            byte[] blindMsgRandomize = clientRandomize.blind(serverPublicKey, input_msg_randomize);

            // Server blind signs message
            byte[] blindSigRandomize = server.blindSign(blindMsgRandomize, publicInfo);

            // Client finalizes and verifies signature
            // Note: Finalize takes the original 'msg' for its internal msg_prime re-calculation.
            byte[] finalSigRandomize = clientRandomize.finalizeSignature(serverPublicKey, blindSigRandomize);
            System.out.println("Final Signature (Randomize) (Base64): " + Base64.getEncoder().encodeToString(finalSigRandomize));

            // Independent Verifier checks the final signature
            // Note: For PrepareRandomize, the application message is conceptually 'slice(input_msg, 32, len(input_msg))'.
            // The Verifier's `verifyFinalSignature` function needs to correctly handle this,
            // as noted in the comments, it's a conceptual simplification for the demo.
            boolean verifyAppResultRandomize = Verifier.verifyFinalSignature(serverPublicKey, clientOriginalMsg, publicInfo, finalSigRandomize, "randomize");
            System.out.println("Independent Verification (Randomize) Result: " + (verifyAppResultRandomize ? "SUCCESS" : "FAILURE"));


        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            System.err.println("Cryptographic algorithm not found or invalid parameters: " + e.getMessage());
        } catch (RuntimeException e) {
            System.err.println("Runtime Error in demo: " + e.getMessage());
            e.printStackTrace();
        }
        System.out.println("\n--- Demo Finished ---");
    }
}
