package gs.simulator.exception;

/**
 * Created by A_Tofigh at 07/16/2024
 */
public class GsException extends Exception {
    protected String errorCode;
    protected String localMessage;

    public GsException() {}

    public GsException(String message) {
        super(message);
    }

    public GsException(Throwable cause) {
        super(cause);
    }

    public GsException(Throwable cause, String errorCode) {
        super(cause);
        this.errorCode = errorCode;
    }

    public GsException(String message, Throwable cause) {
        super(message, cause);
    }

    public GsException(
            String message, Throwable cause,
            boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

    public GsException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    public GsException(String message, Throwable cause, String errorCode) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public GsException(
            String message, String errorCode, String localMessage) {
        super(message);
        this.errorCode = errorCode;
        this.localMessage = localMessage;
    }

    public GsException(
            String message, Throwable cause,
            String errorCode, String localMessage) {
        super(message, cause);
        this.errorCode = errorCode;
        this.localMessage = localMessage;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public void setErrorCode(String errorCode) {
        this.errorCode = errorCode;
    }

    public String getLocalMessage() {
        return localMessage;
    }

    public void setLocalMessage(String localMessage) {
        this.localMessage = localMessage;
    }
}
