package gs.simulator.exception;

/**
 * @author Reza Shojaee, 3/29/2015 06:43 PM
 */
public class GsSecurityException extends GsException {
    public static final String UNREGISTERED_SECURITY_HANDLERS =
            "No security handler could be resolved for the given transaction; "
                    + "unregistered security handler name: %s";
    public static final String UNKNOWN_CRYPTO_ALGORITHM =
            "The given cryptographic algorithm does not identify any known "
                    + "algorithms in system; invalid algorithm: %s";
    public static final String UNKNOWN_CRYPTO_MODE =
            "The given cryptographic mode does not identify any known "
                    + "modes in system; invalid mode: %s";
    public static final String UNKNOWN_CRYPTO_PADDING =
            "The given cryptographic padding does not identify any known "
                    + "paddings in system; invalid padding: %s";
    public static final String UNKNOWN_DIGEST_ALGORITHM =
            "The given algorithm does not identify any known digest "
                    + "algorithms in system; invalid digest algorithm: %s";
    public static final String UNKNOWN_ALGORITHM_KEY =
            "The given algorithm key (coords) does not identify any known "
                    + "keys in system; invalid algorithm key: %s";
    public static final String UNKNOWN_ALGORITHM_AND_KEY_LENGTH_COMBO =
            "The given algorithm and key length combo does not identify any "
                    + "known algorithm key (coords) in system; algorithm "
                    + "part: %s, key length part: %s";
    public static final String UNKNOWN_KEY_TYPE_NAME =
            "The given name does not identify any known key types in system; "
                    + "invalid key type name: %s";
    public static final String UNKNOWN_KEY_TYPE_CODE =
            "The given code does not identify any known key types in system; "
                    + "invalid key type code: %s";
    public static final String UNKNOWN_PIN_BLOCK_METHOD_CODE =
            "The given code does not identify any known pin block methods "
                    + "in system; invalid pin block method code: %s";
    public static final String UNKNOWN_PIN_BLOCK_METHOD_NAME =
            "The given name does not identify any known pin block methods "
                    + "in system; invalid pin block method name: %s";
    public static final String UNKNOWN_MAC_METHOD_CODE =
            "The given code does not identify any known mac methods in "
                    + "system; invalid mac method code: %s";
    public static final String UNKNOWN_MAC_METHOD_NAME =
            "The given name does not identify any known mac methods in "
                    + "system; invalid mac method name: %s";
    public static final String UNKNOWN_CRYPTOGRAPHIC_MODE_CODE =
            "The given code does not identify any known cryptographic modes "
                    + "in system; invalid cryptographic mode code: %s";
    public static final String UNKNOWN_CRYPTOGRAPHIC_MODE_NAME =
            "The given name does not identify any known cryptographic modes "
                    + "in system; invalid cryptographic mode name: %s";
    public static final String UNKNOWN_CRYPTOGRAPHIC_MODE_KEY_COORDS =
            "The given key coords does not identify any known cryptographic "
                    + "modes in system; invalid mode key coords: %s";
    public static final String GENERATED_KEY_FORMAT_NOT_RAW =
            "The generated key format turned out not to be 'RAW' which was "
                    + "highly unexpected; actual format: %s, algorithm: %s";
    public static final String EXPECTED_KEY_NOT_FOUND_IN_KEY_STORE =
            "The cryptography key not found in key store; alias: %s, "
                    + "key store: %s";
    public static final String NO_LMK_FOUND_AS_PARENT_OF_KEY =
            "No local master key found as the parent of the given key; "
                    + "key type: %s";
    public static final String PARENT_KEY_NOT_FOUND =
            "Parent (key-encrypting) key for the given key not found; "
                    + "parent token: %s";
    public static final String WEAK_KEY_INJECT =
            "The specified key is a weak one so cannot be injected into "
                    + "security module; key token: %s, key type: %s";
    public static final String UNADJUSTED_PARITY_KEY_INJECT =
            "The specified key's parity bits are not adjusted so cannot be "
                    + "injected into security module; key token: %s, "
                    + "key type: %s";
    public static final String PIN_KEY_NOT_FOUND =
            "Pin key for the requested operation not found; key token: %s";
    public static final String MAC_KEY_NOT_FOUND =
            "Mac key for the requested operation not found; key token: %s";
    public static final String BASE_DERIVATION_KEY_NOT_FOUND =
            "Base derivation key for the requested operation not found; "
                    + "base key token: %s";
    public static final String CRYPTOGRAPHY_KEY_NOT_FOUND =
            "Cryptography key for the requested operation not found; "
                    + "key token: %s";
    public static final String PIN_ALGORITHM_MISMATCH =
            "The request pin algorithm and configured (supported) pin "
                    + "algorithm for security handler do not match; request "
                    + "pin algorithm: %s, configured pin algorithm: %s";
    public static final String PIN_CRYPTO_METHOD_MISMATCH =
            "The request pin crypto method and configured (supported) pin "
                    + "crypto method for security handler do not match; "
                    + "request pin crypto method: %s, "
                    + "configured pin crypto method: %s";
    public static final String CSD_CRYPTO_METHOD_MISMATCH =
            "The request csd crypto method and configured (supported) csd "
                    + "crypto method for security handler do not match; "
                    + "request csd algorithm: %s, configured csd algorithm: %s";
    public static final String KEY_LENGTH_MISMATCH =
            "The actual key bytes length and reported length in key exchange "
                    + "transaction do not match; actual key bytes length: %s, "
                    + "reported length in security control info: %s";
    public static final String PIN_KEY_LENGTH_MISMATCH =
            "The request pin key length and configured (supported) pin key "
                    + "length for security handler do not match; request pin "
                    + "key length: %s, configured pin key length: %s";
    public static final String REQUEST_PIN_KEY_CONFLICT =
            "Pin key length and encryption method key length in request are "
                    + "in conflict with each other (specify two different "
                    + "values); pin key length: %s, method key length: %s";
    public static final String MAC_KEY_LENGTH_MISMATCH =
            "The request mac key length and configured (supported) mac key "
                    + "length for security handler do not match; request mac "
                    + "key length: %s, configured mac key length: %s";
    public static final String WRONG_SECURITY_HANDLER_FOR_LOCAL =
            "This shetab security handler cannot perform local-to-local pin "
                    + "translation";
    public static final String SHETAB_TO_SHETAB_PIN_OR_CSD_TRANSLATION =
            "Pin or csd translation from shetab to shetab is not supported";
    public static final String EXPECTED_TWO_SECURITY_HANDLERS =
            "Expected two security handlers be involved in pin or csd "
                    + "translation (check your configuration); number of "
                    + "found security handlers: %s";
    public static final String OPAQUE_TOKEN_NOT_FOUND =
            "Mapped opaque token for the give readable token not found; "
                    + "readable key token; %s";
    public static final String KEY_CHECK_VALUE_MISMATCH =
            "Provided key check value does not match our computed one; "
                    + "reference key check value: %s, "
                    + "computed key check value: %s";
    public static final String KEY_CHECK_VALUE_NOT_SUPPORTED =
            "Key check value verification for the given key algorithm is not "
                    + "supported by system; requested key algorithm: %s";
    public static final String PIN_BLOCK_METHOD_NOT_SUPPORTED =
            "The given pin block method is not supported by system; requested "
                    + "pin block method: %s";
    public static final String PIN_BLOCK_METHOD_MISMATCH =
            "Request pin block method and configured (supported) one do not "
                    + "match; request pin block method: %s, "
                    + "configured pin block method: %s";
    public static final String MAC_METHOD_NOT_SUPPORTED =
            "The given mac calculation method is not supported by system; "
                    + "requested mac method: %s";
    public static final String UNKNOWN_KEY_TYPE_EXCHANGED =
            "The given key type is not recognized by the system; "
                    + "invalid key type code; %s";
    public static final String KEY_SET_SIZE_MISMATCH =
            "The request key set size and configured (supported) one for "
                    + "security handler do not match; request key set size: "
                    + "%s, configured key set size: %s";
    public static final String UNKNOWN_CARD_SENSITIVE_ITEM =
            "The given field does not correspond to any known card sensitive "
                    + "data items; specified field: %s";
    public static final String INVALID_LENGTH_FOR_ENCRYPTED_TRACK2 =
            "The given track2 data is corrupted or not encrypted; expected "
                    + "length: %s, actual length: %s";
    public static final String INVALID_LENGTH_FOR_ENCRYPTED_CVV2 =
            "The given cvv2 data is corrupted or not encrypted; expected "
                    + "length: %s, actual length: %s";
    public static final String INVALID_PIN_LENGTH_PARAMETERS =
            "Assigned PIN length cannot be shorter than PIN check length; "
            + "assigned PIN length: %s, PIN check length: %s";
    public static final String INVALID_VALIDATION_DATA =
            "Invalid input validation data; actual length: %s, "
                    + "required length: 8";
    public static final String SUSPICIOUS_DECIMALIZATION_TABLE =
            "Invalid (suspicious) decimalization table given";
    public static final String INVALID_DECIMALIZATION_TABLE_LENGTH =
            "Invalid input decimalization table; actual length: %s, "
                    + "required length: 16";
    public static final String INVALID_PIN_KEY_LENGTH =
            "Invalid input PIN generation/verification key; actual length: %s, "
                    + "required length: 16/24";
    public static final String INVALID_CVV_DATA =
            "Invalid input CVV data; actual length: %s, "
                    + "required length: 16";
    public static final String INVALID_CVV_KEY_LENGTH =
            "Invalid input CVV generation/verification key; actual length: %s, "
                    + "required length: 16/24";
    public static final String INVALID_CVV_LENGTH_PARAMETER =
            "CVV length cannot be shorter than 3; given CVV length: %s";
    public static final String NOT_AUTHORIZED_TO_RUN_COMMAND =
            "You are not authorized to execute the command";

    public GsSecurityException() {
    }

    public GsSecurityException(String message) {
        super(message);
    }

    public GsSecurityException(Throwable cause) {
        super(cause);
    }

    public GsSecurityException(String message, Throwable cause) {
        super(message, cause);
    }

    public GsSecurityException(
            String message, Throwable cause,
            boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

    public GsSecurityException(String message, String errorCode) {
        super(message, errorCode);
    }

    public GsSecurityException(
            String message, Throwable cause, String errorCode) {
        super(message, cause, errorCode);
    }

    public GsSecurityException(
            String message, String errorCode, String localMessage) {
        super(message, errorCode, localMessage);
    }

    public GsSecurityException(
            String message, Throwable cause,
            String errorCode, String localMessage) {
        super(message, cause, errorCode, localMessage);
    }
}
