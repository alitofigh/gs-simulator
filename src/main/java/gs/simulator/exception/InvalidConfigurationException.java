package gs.simulator.exception;

/**
 * Created by A_Tofigh at 08/02/2024
 */
public class InvalidConfigurationException extends GsRuntimeException {
    public final static String INVALID_ARRAY_LENGTH_MESSAGE =
            "Invalid array length: %s";
    public final static String INVALID_VALUE_REFERENCE_MESSAGE =
            "Value reference has not been closed properly; invalid reference "
                    + "descriptor: '%s'";
    public final static String INVALID_VALUE_PROVIDER_MESSAGE =
            "Value provider has not been closed properly; invalid reference "
                    + "descriptor: '%s'";
    public final static String INVALID_ELEMENT_NAME_MESSAGE =
            "Expected a different element name to extract configuration from; "
                    + "expected element: '%s', actual element: '%s'";
    public final static String UNKNOWN_CRITERION_TYPE_MESSAGE =
            "The given criterion element is not of any defined types "
                    + "recognized in system";
    public final static String CRITERION_PARSING_MESSAGE =
            "The given criterion element cannot be parsed correctly; "
                    + "parent position: %s, own position: %s";
    public final static String CRITERIA_PARSING_MESSAGE =
            "The given criteria element cannot be parsed correctly; "
                    + "parent position: %s, own position: %s";
    public final static String UNDEFINED_INSTITUTION_NAME_MESSAGE =
            "The given financial institution is not defined in system; "
                    + "invalid name: '%s'";
    public final static String UNDEFINED_CARD_PRODUCT_MESSAGE =
            "The given card product is not defined in system; invalid name: "
                    + "'%s'";
    public final static String UNRESOLVED_VALUE_REFERENCE_MESSAGE =
            "The given value reference was not resolved via provided "
                    + "resolver elements; invalid value reference: '%s'";
    public final static String MISSING_CONFIGURATION_ITEM_MESSAGE =
            "Expected configuration item not found; missing item: '%s'";
    public final static String INVALID_SWITCH_IIN_MESSAGE =
            "The given switch iin is not valid, it must be a six/nine-digit "
                    + "number; invalid switch iin: '%s'";
    public final static String INVALID_ALTERNATIVE_IIN_MESSAGE =
            "The given alternative iin is not valid, it must be a "
                    + "six/nine-digit number; invalid alternative iin: '%s'";
    public final static String INVALID_CHANNEL_ID_MESSAGE =
            "The given channel id is not valid, it must be a two-digit "
                    + "number; invalid channel id: '%s'";
    public final static String EXPECTED_KEY_VALUE_MESSAGE =
            "Expected a key value pair";
    public final static String NO_SOURCE_ITEMS_FOR_TRANSFORMATION_MESSAGE =
            "No source items specified for transformation";
    public final static String NO_SOURCE_RANGES_FOR_TRANSFORMATION_MESSAGE =
            "No source value range(s) specified for transformation";
    public final static String NO_TARGET_RANGES_FOR_TRANSFORMATION_MESSAGE =
            "No target value range specified for transformation";
    public final static String NOR_TARGET_FOR_TRANSFORMATION_MESSAGE =
            "No target item specified for transformation";
    public final static String EXPECTED_TRANSFORMATION_ELEMENT_MESSAGE =
            "Expected 'transformation' element but got '%s'";

    public InvalidConfigurationException() {
    }

    public InvalidConfigurationException(String message) {
        super(message);
    }

    public InvalidConfigurationException(Throwable cause) {
        super(cause);
    }

    public InvalidConfigurationException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidConfigurationException(
            String message, Throwable cause,
            boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

    public InvalidConfigurationException(String message, String errorCode) {
        super(message, errorCode);
    }

    public InvalidConfigurationException(
            String message, Throwable cause, String errorCode) {
        super(message, cause, errorCode);
    }

    public InvalidConfigurationException(
            String message, String errorCode, String localMessage) {
        super(message, errorCode, localMessage);
    }

    public InvalidConfigurationException(
            String message, Throwable cause,
            String errorCode, String localMessage) {
        super(message, cause, errorCode, localMessage);
    }

}
