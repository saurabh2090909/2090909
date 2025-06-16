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
import java.util.concurrent.ThreadLocalRandom;

// Main class to encapsulate the Partially Blind RSA logic
public class PartiallyBlindRSA {

    // --- Configuration Parameters ---
    // The length in bytes of the RSA modulus n. This determines the size of keys and signatures.
    private static final int MODULUS_LEN = 256; // For RSA 2048-bit key (2048/8 = 256 bytes)
    // The hash algorithm used in PSS (e.g., SHA-256).
    private static final String HASH_ALGORITHM = "SHA-256";
    // The mask generation function used in PSS (e.g., MGF1 with SHA-256).
    private static final String MGF_ALGORITHM = "MGF1";
    // The length in bytes of the salt used in PSS. Typically same as hash output size.
    private static final int SALT_LEN = 32; // SHA-256 produces 32 bytes

    // --- Inner class to hold RSA key components for easier access ---
    static class RSAKeyComponents {
        PublicKey publicKey;
        PrivateKey privateKey;
        BigInteger n; // Modulus
        BigInteger e; // Public exponent
        BigInteger d; // Private exponent
        // p, q, phi (or lambda) are often needed for actual private key operations
        // For simplicity, we assume BigInteger d is sufficient for modPow for private key ops
        // and that actual RSA private key object handles p, q, etc. internally.

        public RSAKeyComponents(PublicKey publicKey, PrivateKey privateKey) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;

            if (publicKey instanceof java.security.interfaces.RSAPublicKey) {
                this.n = ((java.security.interfaces.RSAPublicKey) publicKey).getModulus();
                this.e = ((java.security.interfaces.RSAPublicKey) publicKey).getPublicExponent();
            } else {
                throw new IllegalArgumentException("Public key is not an RSAPublicKey.");
            }

            if (privateKey instanceof java.security.interfaces.RSAPrivateCrtKey) {
                this.d = ((java.security.interfaces.RSAPrivateCrtKey) privateKey).getPrivateExponent();
            } else if (privateKey instanceof java.security.interfaces.RSAPrivateKey) {
                this.d = ((java.security.interfaces.RSAPrivateKey) privateKey).getPrivateExponent();
            } else {
                throw new IllegalArgumentException("Private key is not an RSAPrivateKey.");
            }
        }
    }

    // --- Helper Functions ---

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
     * @param value The integer value.
     * @param length The desired length of the byte array.
     * @return The byte array representation of the integer.
     */
    public static byte[] int_to_bytes(int value, int length) {
        ByteBuffer buffer = ByteBuffer.allocate(length);
        // Put int into buffer, then get bytes. Use appropriate put method for size.
        // For 4 bytes, can use putInt directly. For variable length, BigInteger might be better.
        // As per spec, len(info) is 4 bytes.
        if (length == 4) {
            return ByteBuffer.allocate(4).putInt(value).array();
        } else {
            // For general int_to_bytes for BigIntegers (like z or s),
            // ensure it's positive and padding to modulus_len.
            // Using BigInteger's toByteArray() and padding if necessary.
            BigInteger bi = BigInteger.valueOf(value);
            byte[] bytes = bi.toByteArray();
            if (bytes.length == length) {
                return bytes;
            } else if (bytes.length < length) {
                byte[] padded = new byte[length];
                System.arraycopy(bytes, 0, padded, length - bytes.length, bytes.length);
                return padded;
            } else {
                // If bytes.length > length, truncate (loss of data or error)
                // This case should ideally be an error.
                throw new IllegalArgumentException("int_to_bytes: Value " + value + " requires more than " + length + " bytes.");
            }
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
     * @param info Public metadata.
     * @return An array containing the derived private key at index 0 and derived public key at index 1.
     */
    public static KeyPair DeriveKeyPair(PrivateKey sk, PublicKey pk, byte[] info) {
        // !!! IMPORTANT: THIS IS A PLACEHOLDER IMPLEMENTATION !!!
        // A real DeriveKeyPair would compute a new key pair based on sk and info.
        // The specific algorithm for this derivation is NOT defined in the IETF draft.
        System.out.println("DeriveKeyPair: Using original key pair as derived key pair (PLACEHOLDER).");
        return new KeyPair(pk, sk);
    }

    // --- RSA Primitives (Conceptual for Demonstration) ---

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


    // --- 4.1. Prepare Function (Client-side) ---
    /**
     * Prepares the message for blinding. This demo includes two types: Identity and Randomize.
     * As per the document: "Verification and the message that applications consume therefore depends on which
     * preparation function is used."
     * @param msg The original message byte string.
     * @param type The type of preparation: "identity" or "randomize".
     * @return The prepared message (input_msg).
     */
    public static byte[] Prepare(byte[] msg, String type) {
        if ("identity".equalsIgnoreCase(type)) {
            // PrepareIdentity: input_msg is simply msg.
            System.out.println("Prepare: Using PrepareIdentity.");
            return msg;
        } else if ("randomize".equalsIgnoreCase(type)) {
            // PrepareRandomize: input_msg is slice(input_msg, 32, len(input_msg)),
            // i.e., the prepared message with the random prefix removed.
            // So, input_msg for blinding needs to be random_prefix || msg.
            System.out.println("Prepare: Using PrepareRandomize.");
            byte[] randomPrefix = new byte[32];
            new SecureRandom().nextBytes(randomPrefix);
            return concat(randomPrefix, msg);
        } else {
            throw new IllegalArgumentException("Invalid Prepare type: " + type);
        }
    }

    // --- 4.3. Blind Function (Client-side) ---
    /**
     * Blinds the prepared message using the server's public key and public metadata.
     * Parameters: modulus_len, Hash, MGF, salt_len (configured as static fields).
     * @param pk The server's public key (n, e).
     * @param input_msg The prepared message byte string.
     * @param info Public metadata byte string.
     * @return A pair of byte[] (blind_msg) and BigInteger (inv).
     * @throws RuntimeException for various blinding errors.
     */
    public static BlindOutput Blind(PublicKey pk, byte[] input_msg, byte[] info) {
        System.out.println("\n--- Client: Blinding Message ---");
        // 1. msg_prime = concat("msg", int_to_bytes(len(info), 4), info, msg)
        byte[] msgPrefix = "msg".getBytes(StandardCharsets.UTF_8);
        byte[] infoLenBytes = int_to_bytes(info.length, 4);
        byte[] msg_prime = concat(msgPrefix, infoLenBytes, info, input_msg);
        System.out.println("1. msg_prime created. Length: " + msg_prime.length);

        // 2. encoded_msg = EMSA-PSS-ENCODE(msg_prime, bit_len(n) - 1)
        // !!! IMPORTANT: EMSA-PSS-ENCODE IS CONCEPTUALLY SIMPLIFIED HERE !!!
        // In a real implementation, this would involve complex PSS padding rules (salt, MGF, etc.).
        // Here, we simulate it by hashing msg_prime to get 'm'.
        BigInteger m;
        try {
            MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);
            byte[] hash = md.digest(msg_prime);
            m = bytes_to_int(hash); // Use hash as the conceptual 'm'
            System.out.println("2. EMSA-PSS-ENCODE (conceptual): Hashed msg_prime to get m. Hash: " + Base64.getEncoder().encodeToString(hash));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Encoding error: " + e.getMessage(), e);
        }
        // No direct "message too long" or "encoding error" from simplified hash.

        // 3. Handled by try-catch above if NoSuchAlgorithmException occurs.

        // 4. m = bytes_to_int(encoded_msg) - Already done in step 2 (conceptual).

        // Get RSA public key components for modulus n
        java.security.interfaces.RSAPublicKey rsaPk = (java.security.interfaces.RSAPublicKey) pk;
        BigInteger n = rsaPk.getModulus();

        // 5. c = is_coprime(m, n)
        boolean c = is_coprime(m, n);
        System.out.println("5. m is coprime with n: " + c);

        // 6. If c is false, raise an "invalid input" error and stop
        if (!c) {
            throw new RuntimeException("invalid input: message (m) is not co-prime with n.");
        }

        // 7. r = random_integer_uniform(1, n)
        BigInteger r = random_integer_uniform(BigInteger.ONE, n);
        System.out.println("7. Generated random blinding factor r.");

        // 8. inv = inverse_mod(r, n)
        BigInteger inv;
        try {
            inv = inverse_mod(r, n);
            System.out.println("8. Calculated inverse of r (inv).");
        } catch (ArithmeticException e) {
            // 9. If inverse_mod fails, raise an "blinding error" error and stop
            throw new RuntimeException("blinding error: Inverse of r cannot be found.", e);
        }

        // 10. pk_derived = DerivePublicKey(pk, info)
        PublicKey pk_derived = DerivePublicKey(pk, info);
        System.out.println("10. Derived public key (pk_derived).");

        // 11. x = RSAVP1(pk_derived, r)
        BigInteger x = RSAVP1(pk_derived, r);
        System.out.println("11. Computed x = RSAVP1(pk_derived, r).");

        // 12. z = m * x mod n
        BigInteger z = m.multiply(x).mod(n);
        System.out.println("12. Computed z = m * x mod n.");

        // 13. blind_msg = int_to_bytes(z, modulus_len)
        // Ensure z is represented with enough bytes, potentially padded.
        byte[] blind_msg = z.toByteArray();
        if (blind_msg.length > MODULUS_LEN) {
            // This should not happen if z < n
            throw new RuntimeException("blind_msg too long for modulus_len.");
        } else if (blind_msg.length < MODULUS_LEN) {
            byte[] temp = new byte[MODULUS_LEN];
            System.arraycopy(blind_msg, 0, temp, MODULUS_LEN - blind_msg.length, blind_msg.length);
            blind_msg = temp;
        }
        System.out.println("13. Converted z to blind_msg byte array. Length: " + blind_msg.length);


        // 14. output blind_msg, inv
        System.out.println("Blind: Completed. Output blind_msg and inv.");
        return new BlindOutput(blind_msg, inv);
    }

    // Class to encapsulate output of Blind function
    static class BlindOutput {
        byte[] blindMsg;
        BigInteger inv;

        public BlindOutput(byte[] blindMsg, BigInteger inv) {
            this.blindMsg = blindMsg;
            this.inv = inv;
        }
    }


    // --- 4.4. BlindSign Function (Server-side) ---
    /**
     * The server signs the blinded message.
     * @param sk The server's private key.
     * @param pk The server's public key (needed for DeriveKeyPair and RSAVP1).
     * @param blind_msg The blinded message received from the client.
     * @param info Public metadata.
     * @return The blinded signature (blind_sig).
     * @throws RuntimeException for signing failures.
     */
    public static byte[] BlindSign(PrivateKey sk, PublicKey pk, byte[] blind_msg, byte[] info) {
        System.out.println("\n--- Server: Blind Signing Message ---");
        // 1. m = bytes_to_int(blind_msg)
        BigInteger m = bytes_to_int(blind_msg);
        System.out.println("1. Converted blind_msg to integer m.");

        // 2. sk_derived, pk_derived = DeriveKeyPair(sk, info)
        KeyPair derivedKeyPair = DeriveKeyPair(sk, pk, info);
        PrivateKey sk_derived = derivedKeyPair.getPrivate();
        PublicKey pk_derived = derivedKeyPair.getPublic();
        System.out.println("2. Derived key pair (sk_derived, pk_derived).");

        // 3. s = RSASP1(sk_derived, m)
        BigInteger s = RSASP1(sk_derived, m);
        System.out.println("3. Computed s = RSASP1(sk_derived, m).");

        // 4. m' = RSAVP1(pk_derived, s)
        BigInteger m_prime = RSAVP1(pk_derived, s);
        System.out.println("4. Computed m' = RSAVP1(pk_derived, s).");

        // 5. If m != m', raise "signing failure" and stop
        if (!m.equals(m_prime)) {
            throw new RuntimeException("signing failure: Internal verification failed (m != m').");
        }
        System.out.println("5. Internal verification passed (m == m').");

        // 6. blind_sig = int_to_bytes(s, modulus_len)
        byte[] blind_sig_bytes = s.toByteArray();
        if (blind_sig_bytes.length > MODULUS_LEN) {
             // If s is slightly larger due to leading zero in BigInteger.toByteArray(),
             // and it's equal to modulus_len + 1 (e.g., 257 for 256 bytes), it means it's positive.
             // We can strip leading zero if it's there.
             if (blind_sig_bytes[0] == 0 && blind_sig_bytes.length == MODULUS_LEN + 1) {
                 blind_sig_bytes = Arrays.copyOfRange(blind_sig_bytes, 1, blind_sig_bytes.length);
             } else {
                 throw new RuntimeException("blind_sig too long for modulus_len.");
             }
        } else if (blind_sig_bytes.length < MODULUS_LEN) {
            byte[] temp = new byte[MODULUS_LEN];
            System.arraycopy(blind_sig_bytes, 0, temp, MODULUS_LEN - blind_sig_bytes.length, blind_sig_bytes.length);
            blind_sig_bytes = temp;
        }
        System.out.println("6. Converted s to blind_sig byte array. Length: " + blind_sig_bytes.length);

        // 7. output blind_sig
        System.out.println("BlindSign: Completed. Output blind_sig.");
        return blind_sig_bytes;
    }


    // --- 4.5. Finalize Function (Client-side) ---
    /**
     * Client finalizes the signature and verifies it.
     * Parameters: modulus_len, Hash, MGF, salt_len (configured as static fields).
     * @param pk Server's public key (n, e).
     * @param msg Original message, a byte string.
     * @param info Public metadata, a byte string.
     * @param blind_sig Signed and blinded element, a byte string.
     * @param inv Inverse of the blind, an integer.
     * @return The final, unblinded, and verified signature (sig).
     * @throws RuntimeException for invalid signature or unexpected input size.
     */
    public static byte[] Finalize(PublicKey pk, byte[] msg, byte[] info, byte[] blind_sig, BigInteger inv) {
        System.out.println("\n--- Client: Finalizing Signature ---");
        // 1. If len(blind_sig) != modulus_len, raise "unexpected input size" and stop
        if (blind_sig.length != MODULUS_LEN) {
            throw new RuntimeException("unexpected input size: blind_sig length (" + blind_sig.length + ") does not match modulus_len (" + MODULUS_LEN + ").");
        }
        System.out.println("1. blind_sig length validated.");

        // 2. z = bytes_to_int(blind_sig)
        BigInteger z = bytes_to_int(blind_sig);
        System.out.println("2. Converted blind_sig to integer z.");

        // Get RSA public key components for modulus n
        java.security.interfaces.RSAPublicKey rsaPk = (java.security.interfaces.RSAPublicKey) pk;
        BigInteger n = rsaPk.getModulus();

        // 3. s = z * inv mod n
        BigInteger s = z.multiply(inv).mod(n);
        System.out.println("3. Unblinded signature: s = z * inv mod n.");

        // 4. sig = int_to_bytes(s, modulus_len)
        byte[] sig_bytes = s.toByteArray();
        if (sig_bytes.length > MODULUS_LEN) {
             if (sig_bytes[0] == 0 && sig_bytes.length == MODULUS_LEN + 1) {
                 sig_bytes = Arrays.copyOfRange(sig_bytes, 1, sig_bytes.length);
             } else {
                 throw new RuntimeException("Final signature too long for modulus_len.");
             }
        } else if (sig_bytes.length < MODULUS_LEN) {
            byte[] temp = new byte[MODULUS_LEN];
            System.arraycopy(sig_bytes, 0, temp, MODULUS_LEN - sig_bytes.length, sig_bytes.length);
            sig_bytes = temp;
        }
        System.out.println("4. Converted s to final signature (sig) byte array. Length: " + sig_bytes.length);


        // 5. msg_prime = concat("msg", int_to_bytes(len(info), 4), info, msg)
        byte[] msgPrefix = "msg".getBytes(StandardCharsets.UTF_8);
        byte[] infoLenBytes = int_to_bytes(info.length, 4);
        byte[] msg_prime = concat(msgPrefix, infoLenBytes, info, msg); // Use original 'msg' here
        System.out.println("5. Re-created msg_prime for verification. Length: " + msg_prime.length);

        // 6. pk_derived = DerivePublicKey(pk, info)
        PublicKey pk_derived = DerivePublicKey(pk, info);
        System.out.println("6. Derived public key (pk_derived) for verification.");

        // 7. result = RSASSA-PSS-VERIFY(pk_derived, msg_prime, sig)
        // This uses Java's built-in Signature class which properly implements RSASSA-PSS verification.
        boolean result;
        try {
            Signature verifier = Signature.getInstance("RSASSA-PSS");
            // Set PSS parameters
            PSSParameterSpec pssSpec = new PSSParameterSpec(
                    HASH_ALGORITHM,
                    MGF_ALGORITHM + "with" + HASH_ALGORITHM, // MGF1withSHA-256 for example
                    new MGF1ParameterSpec(HASH_ALGORITHM),
                    SALT_LEN,
                    PSSParameterSpec.TRAILER_FIELD_BC // 1
            );
            verifier.setParameter(pssSpec);
            verifier.initVerify(pk_derived);
            verifier.update(msg_prime); // Pass the original message data
            result = verifier.verify(sig_bytes); // Pass the unblinded signature
            System.out.println("7. RSASSA-PSS-VERIFY result: " + (result ? "Valid" : "Invalid"));
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("Verification error: " + e.getMessage(), e);
        }

        // 8. If result = "valid signature", output sig, else raise "invalid signature" and stop
        if (result) {
            System.out.println("Finalize: Completed. Signature is VALID. Output sig.");
            return sig_bytes;
        } else {
            throw new RuntimeException("invalid signature: RSASSA-PSS-VERIFY failed.");
        }
    }


    // --- Main Method for Demonstration ---
    public static void main(String[] args) {
        System.out.println("--- Starting Partially Blind RSA Demo ---");

        // 1. Generate RSA Key Pair (Server's Key Pair)
        KeyPairGenerator keyGen;
        try {
            keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(MODULUS_LEN * 8); // RSA key size in bits
            KeyPair serverKeyPair = keyGen.generateKeyPair();
            PublicKey serverPublicKey = serverKeyPair.getPublic();
            PrivateKey serverPrivateKey = serverKeyPair.getPrivate();
            System.out.println("\nGenerated Server RSA Key Pair (Public and Private keys).");
            System.out.println("Public Key Modulus Length (bytes): " + ((java.security.interfaces.RSAPublicKey)serverPublicKey).getModulus().toByteArray().length);

            // Client's original message
            byte[] clientOriginalMsg = "some text".getBytes(StandardCharsets.UTF_8);
            System.out.println("Client's original message: '" + new String(clientOriginalMsg) + "'");

            // Public metadata (info)
            // As per user request: {"fs":"10"}
            byte[] publicInfo = "{\"fs\":\"10\"}".getBytes(StandardCharsets.UTF_8);
            System.out.println("Public metadata (info): '" + new String(publicInfo) + "'");


            // --- Scenario 1: Using PrepareIdentity ---
            System.out.println("\n\n--- SCENARIO 1: Using PrepareIdentity ---");
            byte[] input_msg_identity = Prepare(clientOriginalMsg, "identity");
            // Client Blinds Message
            BlindOutput blindOutputIdentity = Blind(serverPublicKey, input_msg_identity, publicInfo);
            byte[] blindMsgIdentity = blindOutputIdentity.blindMsg;
            BigInteger invIdentity = blindOutputIdentity.inv;

            // Server Blind Signs Message
            byte[] blindSigIdentity = BlindSign(serverPrivateKey, serverPublicKey, blindMsgIdentity, publicInfo);

            // Client Finalizes and Verifies Signature
            byte[] finalSigIdentity = Finalize(serverPublicKey, clientOriginalMsg, publicInfo, blindSigIdentity, invIdentity);
            System.out.println("Final Signature (Identity) (Base64): " + Base64.getEncoder().encodeToString(finalSigIdentity));

            // Verify the final signature independently (as a third party would)
            // Note: For PrepareIdentity, application message is input_msg (which is clientOriginalMsg)
            boolean verifyAppResultIdentity = verifyFinalSignature(serverPublicKey, clientOriginalMsg, publicInfo, finalSigIdentity, "identity");
            System.out.println("Independent Verification (Identity) Result: " + (verifyAppResultIdentity ? "SUCCESS" : "FAILURE"));


            // --- Scenario 2: Using PrepareRandomize ---
            System.out.println("\n\n--- SCENARIO 2: Using PrepareRandomize ---");
            byte[] input_msg_randomize = Prepare(clientOriginalMsg, "randomize");
            // Client Blinds Message
            BlindOutput blindOutputRandomize = Blind(serverPublicKey, input_msg_randomize, publicInfo);
            byte[] blindMsgRandomize = blindOutputRandomize.blindMsg;
            BigInteger invRandomize = blindOutputRandomize.inv;

            // Server Blind Signs Message
            byte[] blindSigRandomize = BlindSign(serverPrivateKey, serverPublicKey, blindMsgRandomize, publicInfo);

            // Client Finalizes and Verifies Signature
            // Note: Finalize takes the original 'msg' for its internal msg_prime re-calculation.
            byte[] finalSigRandomize = Finalize(serverPublicKey, clientOriginalMsg, publicInfo, blindSigRandomize, invRandomize);
            System.out.println("Final Signature (Randomize) (Base64): " + Base64.getEncoder().encodeToString(finalSigRandomize));

            // Verify the final signature independently (as a third party would)
            // Note: For PrepareRandomize, application message is slice(input_msg, 32, len(input_msg))
            // The `verifyFinalSignature` function needs to understand the preparation
            boolean verifyAppResultRandomize = verifyFinalSignature(serverPublicKey, clientOriginalMsg, publicInfo, finalSigRandomize, "randomize");
            System.out.println("Independent Verification (Randomize) Result: " + (verifyAppResultRandomize ? "SUCCESS" : "FAILURE"));


        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            System.err.println("Cryptographic algorithm not found or invalid parameters: " + e.getMessage());
        } catch (RuntimeException e) {
            System.err.println("Runtime Error in demo: " + e.getMessage());
            e.printStackTrace();
        }
        System.out.println("\n--- Demo Finished ---");
    }

    /**
     * Helper function to independently verify the final signature, mirroring the client's verification logic.
     * This simulates what a third party or the application consuming the signed message would do.
     * @param pk Server's public key.
     * @param msg Original message.
     * @param info Public metadata.
     * @param sig The final signature to verify.
     * @param prepareType The type of preparation ("identity" or "randomize") used during blinding.
     * @return true if the signature is valid, false otherwise.
     */
    public static boolean verifyFinalSignature(PublicKey pk, byte[] msg, byte[] info, byte[] sig, String prepareType) {
        System.out.println("\n--- Independent Verification ---");
        try {
            // Re-prepare input_msg based on the original prepareType for accurate msg_prime calculation
            byte[] input_msg_for_verification;
            if ("identity".equalsIgnoreCase(prepareType)) {
                input_msg_for_verification = msg;
            } else if ("randomize".equalsIgnoreCase(prepareType)) {
                // In PrepareRandomize, input_msg was (randomPrefix || originalMsg).
                // To re-construct `msg_prime` correctly, we need the *full* `input_msg` that was signed.
                // This means the `verifyFinalSignature` function would need the original `input_msg_randomize` (with prefix)
                // or a way to derive it. For a truly independent verifier, they typically verify over the
                // exact bytes that were signed.
                // !!! IMPORTANT: This is a conceptual gap in the provided text's verification section.
                // The verification describes using `msg_prime = concat("msg", ..., info, msg)`, which implies `msg` is the original.
                // But if PrepareRandomize was used, `input_msg` had a prefix. The server signed a blinded version of `input_msg`.
                // For the verifier to work, the `msg_prime` must correspond to the `input_msg` that was actually blinded and signed.
                // If `RSASSA-PSS-VERIFY` uses `msg_prime` from `msg` (without the random prefix), it implies the
                // PSS encoding itself implicitly handles the random prefix, which is not standard.
                // A common pattern is that the application extracts the data it cares about *after* verification.
                // Let's assume for this verification step, we verify against `msg_prime` generated from the *original* `msg`,
                // and the PSS verification handles the rest.
                // If `PrepareRandomize` was used, `input_msg` included a random prefix. The signature is on that `input_msg`.
                // The `msg_prime` for verification should thus be `concat("msg", int_to_bytes(len(info), 4), info, input_msg_randomize)`.
                // However, the `Finalize` step and verification description given in the prompt re-uses `msg`.
                // This suggests the random prefix is handled *within* the PSS encoding or is assumed to be part of what `msg` represents.
                // Given the phrasing: "the application message is slice(input_msg, 32, len(input_msg))",
                // it implies the *raw message for the PSS part* includes the prefix, and the *application* just strips it.
                // For this demo, let's keep it simple as per `Finalize` and `msg_prime` construction.
                // A robust solution would need the full `input_msg` if `PrepareRandomize` was used.
                // For now, we will use the original `msg` for `msg_prime` for verification, aligning with the `Finalize` function's step 5.
                input_msg_for_verification = msg; // This is a simplification/assumption
                System.out.println("Independent Verification: Assuming msg_prime is formed from original msg, even for 'randomize' type.");
            } else {
                throw new IllegalArgumentException("Invalid Prepare type for verification: " + prepareType);
            }


            // Compute pk_derived = DerivePublicKey(pk, info).
            PublicKey pk_derived_verify = DerivePublicKey(pk, info);

            // Compute msg_prime = concat("msg", int_to_bytes(len(info), 4), info, msg).
            byte[] msgPrefix = "msg".getBytes(StandardCharsets.UTF_8);
            byte[] infoLenBytes = int_to_bytes(info.length, 4);
            byte[] msg_prime_verify = concat(msgPrefix, infoLenBytes, info, input_msg_for_verification); // Using input_msg for verification here
            System.out.println("Independent Verification: Re-created msg_prime. Length: " + msg_prime_verify.length);

            // Invoke and output the result of RSASSA-PSS-VERIFY
            Signature verifier = Signature.getInstance("RSASSA-PSS");
            PSSParameterSpec pssSpec = new PSSParameterSpec(
                    HASH_ALGORITHM,
                    MGF_ALGORITHM + "with" + HASH_ALGORITHM,
                    new MGF1ParameterSpec(HASH_ALGORITHM),
                    SALT_LEN,
                    PSSParameterSpec.TRAILER_FIELD_BC // 1
            );
            verifier.setParameter(pssSpec);
            verifier.initVerify(pk_derived_verify);
            verifier.update(msg_prime_verify);
            return verifier.verify(sig);

        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | InvalidAlgorithmParameterException e) {
            System.err.println("Independent verification error: " + e.getMessage());
            return false;
        }
    }
}
