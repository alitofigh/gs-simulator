package gs.simulator.exception;

/**
 * Created by A_Tofigh at 08/02/2024
 */
public class InvalidCommandException extends GsException {
    public InvalidCommandException() {}

    public InvalidCommandException(String message) {
        super(message);
    }

    public InvalidCommandException(Throwable cause) {
        super(cause);
    }

    public InvalidCommandException(Throwable cause, String errorCode) {
        super(cause, errorCode);
    }

    public InvalidCommandException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidCommandException(
            String message, Throwable cause,
            boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

    public InvalidCommandException(String message, String errorCode) {
        super(message, errorCode);
    }

    public InvalidCommandException(
            String message, Throwable cause, String errorCode) {
        super(message, cause, errorCode);
    }

    public InvalidCommandException(
            String message, String errorCode, String localMessage) {
        super(message, errorCode, localMessage);
    }

    public InvalidCommandException(
            String message, Throwable cause,
            String errorCode, String localMessage) {
        super(message, cause, errorCode, localMessage);
    }
}
