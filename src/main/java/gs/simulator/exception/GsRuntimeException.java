package gs.simulator.exception;

/**
 * Created by A_Tofigh at 07/16/2024
 */
public class GsRuntimeException extends RuntimeException {
    protected String errorCode;
    protected String localMessage;

    public GsRuntimeException() {}

    public GsRuntimeException(String message) {
        super(message);
    }

    public GsRuntimeException(Throwable cause) {
        super(cause);
    }

    public GsRuntimeException(Throwable cause, String errorCode) {
        super(cause);
        this.errorCode = errorCode;
    }

    public GsRuntimeException(String message, Throwable cause) {
        super(message, cause);
    }

    public GsRuntimeException(
            String message, Throwable cause,
            boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

    public GsRuntimeException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    public GsRuntimeException(
            String message, Throwable cause, String errorCode) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public GsRuntimeException(
            String message, String errorCode, String localMessage) {
        super(message);
        this.errorCode = errorCode;
        this.localMessage = localMessage;
    }

    public GsRuntimeException(
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
