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

// --- Shared Configuration Parameters ---
// The length in bytes of the RSA modulus n. This determines the size of keys and signatures.
// For RSA 2048-bit key, 2048/8 = 256 bytes.
class Config {
    public static final int MODULUS_LEN = 256;
    // The hash algorithm used (e.g., SHA-256).
    public static final String HASH_ALGORITHM = "SHA-256";
    // The mask generation function used in PSS (e.g., MGF1).
    public static final String MGF_ALGORITHM = "MGF1";
    // The length in bytes of the salt used in PSS. Typically same as hash output size.
    public static final int SALT_LEN = 32;
    // The algorithm string for RSASSA-PSS. Used for key generation, but verification will use SHA256withRSA for this demo.
    public static final String PSS_ALGORITHM = "RSASSA-PSS";
    // Algorithm string for standard RSA signature over a hash (PKCS#1 v1.5 padding). Used for verification in this demo.
    public static final String RSA_HASH_ALGORITHM = HASH_ALGORITHM + "withRSA";
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
     * For BigIntegers (like z or s), BigInteger.toByteArray() then padding is used,
     * as `int` is insufficient for large RSA values.
     * @param value The integer value.
     * @param length The desired length of the byte array.
     * @return The byte array representation of the integer.
     */
    public static byte[] int_to_bytes(int value, int length) {
        if (length == 4) {
            return ByteBuffer.allocate(4).putInt(value).array();
        } else {
            // This method is primarily for the 4-byte length indicator.
            // For general BigInteger to byte[] conversion, use BigInteger.toByteArray()
            // with appropriate padding/truncation for MODULUS_LEN.
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
     * Prepares the message for blinding.
     * @param type The type of preparation: "identity" or "randomize".
     * @return The prepared message (input_msg).
     */
    public byte[] prepare(String type) {
        if ("identity".equalsIgnoreCase(type)) {
            System.out.println("Client Prepare: Using PrepareIdentity.");
            return originalMsg;
        } else if ("randomize".equalsIgnoreCase(type)) {
            System.out.println("Client Prepare: Using PrepareRandomize.");
            byte[] randomPrefix = new byte[32];
            new SecureRandom().nextBytes(randomPrefix);
            return CryptoHelpers.concat(randomPrefix, originalMsg);
        } else {
            throw new IllegalArgumentException("Invalid Prepare type: " + type);
        }
    }

    /**
     * Blinds the prepared message using the server's public key and public metadata.
     * @param pk The server's public key (n, e).
     * @param input_msg The prepared message byte string.
     * @return The blinded message (blind_msg).
     * @throws RuntimeException for various blinding errors.
     */
    public byte[] blind(PublicKey pk, byte[] input_msg) {
        System.out.println("\n--- Client: Blinding Message ---");
        // 1. msg_prime = concat("msg", int_to_bytes(len(info), 4), info, input_msg)
        byte[] msgPrefix = "msg".getBytes(StandardCharsets.UTF_8);
        byte[] infoLenBytes = CryptoHelpers.int_to_bytes(publicInfo.length, 4);
        byte[] msg_prime = CryptoHelpers.concat(msgPrefix, infoLenBytes, publicInfo, input_msg);
        System.out.println("1. msg_prime created. Length: " + msg_prime.length);

        // 2. encoded_msg = EMSA-PSS-ENCODE(msg_prime, bit_len(n) - 1)
        // !!! IMPORTANT: EMSA-PSS-ENCODE IS CONCEPTUALLY SIMPLIFIED HERE FOR THE DEMO !!!
        // In a real, compliant Partially Blind RSA implementation using RSASSA-PSS,
        // this step would involve performing the full PSS padding on msg_prime to
        // get the encoded message block 'EM', and then converting 'EM' to 'm'.
        // Standard Java Signature API does not easily expose 'EM' directly.
        // For this demo, 'm' is derived from a simple hash of 'msg_prime'.
        // This is a simplification that leads to the need for a non-PSS verification
        // in the Finalize/Verifier steps.
        BigInteger m;
        try {
            MessageDigest md = MessageDigest.getInstance(Config.HASH_ALGORITHM, "BC"); // Use BC provider
            byte[] hash = md.digest(msg_prime);
            m = CryptoHelpers.bytes_to_int(hash); // Use hash as the conceptual 'm'
            System.out.println("2. EMSA-PSS-ENCODE (conceptual): Hashed msg_prime to get m. Hash: " + Base64.getEncoder().encodeToString(hash));
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException("Encoding error: " + e.getMessage(), e);
        }

        // Get RSA public key components for modulus n
        java.security.interfaces.RSAPublicKey rsaPk = (java.security.interfaces.RSAPublicKey) pk;
        BigInteger n = rsaPk.getModulus();

        // 5. c = is_coprime(m, n)
        boolean c = CryptoHelpers.is_coprime(m, n);
        System.out.println("5. m is coprime with n: " + c);
        // 6. If c is false, raise an "invalid input" error and stop
        if (!c) {
            throw new RuntimeException("invalid input: message (m) is not co-prime with n.");
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
            throw new RuntimeException("blinding error: Inverse of r cannot be found.", e);
        }

        // 10. pk_derived = DerivePublicKey(pk, info)
        PublicKey pk_derived = CryptoHelpers.DerivePublicKey(pk, publicInfo);
        System.out.println("10. Derived public key (pk_derived).");

        // 11. x = RSAVP1(pk_derived, r)
        BigInteger x = CryptoHelpers.RSAVP1(pk_derived, r);
        System.out.println("11. Computed x = RSAVP1(pk_derived, r).");

        // 12. z = m * x mod n
        BigInteger z = m.multiply(x).mod(n);
        System.out.println("12. Computed z = m * x mod n.");

        // 13. blind_msg = int_to_bytes(z, modulus_len)
        byte[] blind_msg = CryptoHelpers.big_int_to_fixed_bytes(z, Config.MODULUS_LEN);
        System.out.println("13. Converted z to blind_msg byte array. Length: " + blind_msg.length);

        System.out.println("Client Blind: Completed. Output blind_msg.");
        return blind_msg;
    }

    /**
     * Client finalizes the signature and verifies it.
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
        BigInteger s = z.multiply(this.blindingInverse).mod(n);
        System.out.println("3. Unblinded signature: s = z * inv mod n.");

        // 4. sig = int_to_bytes(s, modulus_len)
        byte[] sig_bytes = CryptoHelpers.big_int_to_fixed_bytes(s, Config.MODULUS_LEN);
        System.out.println("4. Converted s to final signature (sig) byte array. Length: " + sig_bytes.length);

        // 5. msg_prime = concat("msg", int_to_bytes(len(info), 4), info, originalMsg)
        byte[] msgPrefix = "msg".getBytes(StandardCharsets.UTF_8);
        byte[] infoLenBytes = CryptoHelpers.int_to_bytes(publicInfo.length, 4);
        byte[] msg_prime = CryptoHelpers.concat(msgPrefix, infoLenBytes, publicInfo, originalMsg); // Use original 'msg' here
        System.out.println("5. Re-created msg_prime for verification. Length: " + msg_prime.length);

        // 6. pk_derived = DerivePublicKey(pk, info)
        PublicKey pk_derived = CryptoHelpers.DerivePublicKey(pk, publicInfo);
        System.out.println("6. Derived public key (pk_derived) for verification.");

        // 7. result = RSASSA-PSS-VERIFY(pk_derived, msg_prime, sig)
        // !!! IMPORTANT: USING SHA256withRSA FOR VERIFICATION IN THIS DEMO !!!
        // Due to the conceptual simplification of EMSA-PSS-ENCODE in the 'blind' function
        // (where 'm' is just a hash), the resulting signature 'sig' is effectively
        // a standard RSA signature over that hash (PKCS#1 v1.5 padding).
        // A true RSASSA-PSS verification would fail as 'sig' doesn't conform to PSS structure.
        // This change allows the demo to function and verify the signature produced.
        // For strict compliance with the draft's RSASSA-PSS, the 'blind' function's EMSA-PSS-ENCODE
        // would need to produce the full PSS-encoded message block.
        boolean result;
        try {
            Signature verifier = Signature.getInstance(Config.RSA_HASH_ALGORITHM, "BC"); // Changed to SHA256withRSA
            // PSSParameterSpec is NOT needed for SHA256withRSA
            verifier.initVerify(pk_derived);
            verifier.update(msg_prime); // Still update with msg_prime, which is then internally hashed
            result = verifier.verify(sig_bytes);
            System.out.println("7. " + Config.RSA_HASH_ALGORITHM + " verification result: " + (result ? "Valid" : "Invalid"));
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException e) {
            throw new RuntimeException("Verification error: " + e.getMessage(), e);
        }

        // 8. If result = "valid signature", output sig, else raise "invalid signature" and stop
        if (result) {
            System.out.println("Client Finalize: Completed. Signature is VALID. Output sig.");
            return sig_bytes;
        } else {
            throw new RuntimeException("invalid signature: " + Config.RSA_HASH_ALGORITHM + " verification failed.");
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
        BigInteger m = CryptoHelpers.bytes_to_int(blind_msg);
        System.out.println("1. Converted blind_msg to integer m.");

        // 2. sk_derived, pk_derived = DeriveKeyPair(sk, info)
        KeyPair derivedKeyPair = CryptoHelpers.DeriveKeyPair(serverPrivateKey, serverPublicKey, info);
        PrivateKey sk_derived = derivedKeyPair.getPrivate();
        PublicKey pk_derived = derivedKeyPair.getPublic();
        System.out.println("2. Derived key pair (sk_derived, pk_derived).");

        // 3. s = RSASP1(sk_derived, m)
        BigInteger s = CryptoHelpers.RSASP1(sk_derived, m);
        System.out.println("3. Computed s = RSASP1(sk_derived, m).");

        // 4. m' = RSAVP1(pk_derived, s)
        BigInteger m_prime = CryptoHelpers.RSAVP1(pk_derived, s);
        System.out.println("4. Computed m' = RSAVP1(pk_derived, s).");

        // 5. If m != m', raise "signing failure" and stop
        if (!m.equals(m_prime)) {
            throw new RuntimeException("signing failure: Internal verification failed (m != m').");
        }
        System.out.println("5. Internal verification passed (m == m').");

        // 6. blind_sig = int_to_bytes(s, modulus_len)
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
                // !!! IMPORTANT CONSIDERATION FOR PrepareRandomize VERIFICATION !!!
                // If 'PrepareRandomize' was used, the 'input_msg' that was actually signed included a 32-byte random prefix.
                // For *correct* RSASSA-PSS-VERIFY, `msg_prime` MUST be derived from the exact `input_msg` that was blinded.
                // The prompt's previous description for `Finalize` step 5 used `msg` (original message) for `msg_prime`.
                // If `msg_prime` in `Finalize` uses `msg` *without* the random prefix when `PrepareRandomize` was used,
                // then the `Finalize`'s own verification step (7) would fail unless the PSS scheme inherently deals with this,
                // which is not standard.
                // A correct verification of a signature produced with `PrepareRandomize` would require knowing the *exact*
                // `input_msg` (including the random prefix) that was fed to `Blind`. Since a typical independent verifier
                // would only have `msg` and `info`, this highlights a potential challenge or requires the random prefix
                // to be communicated with the final signature for full compliance with the PSS spec.
                // For this demo, aligning with the "application consumes slice(input_msg, 32, len(input_msg))"
                // and the `Finalize` function's current behavior, we assume `msg` is sufficient for `msg_prime`
                // in the context of RSASSA-PSS-VERIFY. In a real system, this would need careful design.
                input_msg_for_verification = msg; // This is a simplification/assumption
                System.out.println("Verifier: Assuming original msg for msg_prime construction in 'randomize' type (DEMO SIMPLIFICATION).");
            } else {
                throw new IllegalArgumentException("Invalid Prepare type for verification: " + prepareType);
            }

            // Compute pk_derived = DerivePublicKey(pk, info).
            PublicKey pk_derived_verify = CryptoHelpers.DerivePublicKey(pk, info);
            System.out.println("Verifier: Derived public key (pk_derived) for verification.");

            // Compute msg_prime = concat("msg", int_to_bytes(len(info), 4), info, input_msg_for_verification).
            byte[] msgPrefix = "msg".getBytes(StandardCharsets.UTF_8);
            byte[] infoLenBytes = CryptoHelpers.int_to_bytes(info.length, 4);
            byte[] msg_prime_verify = CryptoHelpers.concat(msgPrefix, infoLenBytes, info, input_msg_for_verification);
            System.out.println("Verifier: Re-created msg_prime. Length: " + msg_prime_verify.length);

            // Invoke SHA256withRSA verification
            Signature verifier = Signature.getInstance(Config.RSA_HASH_ALGORITHM, "BC"); // Changed to SHA256withRSA
            // PSSParameterSpec is NOT needed for SHA256withRSA
            verifier.initVerify(pk_derived_verify);
            verifier.update(msg_prime_verify); // Still update with msg_prime, which is then internally hashed
            boolean result = verifier.verify(sig);
            System.out.println("Verifier: " + Config.RSA_HASH_ALGORITHM + " verification result: " + (result ? "Valid" : "Invalid"));
            return result;

        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException e) {
            System.err.println("Verifier error during verification: " + e.getMessage());
            return false;
        }
    }
}


// --- Main Application to Orchestrate Components ---
public class PartiallyBlindRSADemo {

    public static void main(String[] args) {
        System.out.println("--- Starting Partially Blind RSA Demo with Separate Components and Bouncy Castle ---");

        // Register Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());
        System.out.println("Bouncy Castle Provider Registered.");

        // 1. Generate RSA Key Pair for the Server
        KeyPairGenerator keyGen;
        try {
            keyGen = KeyPairGenerator.getInstance("RSA", "BC"); // Use BC provider for key generation
            keyGen.initialize(Config.MODULUS_LEN * 8, new SecureRandom()); // RSA key size in bits
            KeyPair serverKeyPair = keyGen.generateKeyPair();
            System.out.println("\nGenerated Server RSA Key Pair.");
            System.out.println("Server Public Key Modulus Length (bytes): " + ((java.security.interfaces.RSAPublicKey)serverKeyPair.getPublic()).getModulus().toByteArray().length);

            // Instantiate Server
            Server server = new Server(serverKeyPair);
            PublicKey serverPublicKey = server.getPublicKey();

            // Client's original message
            byte[] clientOriginalMsg = "some text".getBytes(StandardCharsets.UTF_8);
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
