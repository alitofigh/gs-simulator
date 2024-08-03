package gs.simulator.logging;

import gs.simulator.exception.GsException;
import gs.simulator.exception.GsRuntimeException;
import org.jpos.iso.ISOMsg;
import org.jpos.util.LogEvent;
import org.jpos.util.Logger;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.*;

/**
 * Created by A_Tofigh at 07/16/2024
 */

public class GsLogger extends LoggerBase {
    private static final Set<Class<? extends Throwable>>
            EXCEPTIONS_CONSIDERED_EVENT = new HashSet<>();

    // Don't use static initializer because this class is used in Sima2Main
    // and since it does jPOS logger initialization in its ctor, there may be
    // a chance that logger won't work if this class loaded into memory before
    // jPOS ecosystem is fully operational, instead make an instance in
    // getInstance() method (which is ensured to get called in the right time)
    private static GsLogger instance;
    private static boolean loggerDisabled;

    static {
        // To consider all exceptions as event, simple add Throwable.class below
        // Currently all exceptions not related to user input are deemed event

        // Java platform exceptions
        EXCEPTIONS_CONSIDERED_EVENT.add(FileNotFoundException.class);
        EXCEPTIONS_CONSIDERED_EVENT.add(IOException.class);
        EXCEPTIONS_CONSIDERED_EVENT.add(SocketException.class);
        EXCEPTIONS_CONSIDERED_EVENT.add(SocketTimeoutException.class);
        // Load classes not common for all projects dynamically, be cautious
        try {
            // JAX-WS exceptions
            //noinspection unchecked
            EXCEPTIONS_CONSIDERED_EVENT.add(
                    (Class<? extends Throwable>) Class.forName(
                            "com.sun.xml.ws.client.ClientTransportException"));
            // SoapDust web service client library exceptions
            //noinspection unchecked
            EXCEPTIONS_CONSIDERED_EVENT.add((Class<? extends Throwable>)
                    Class.forName("soapdust.FaultResponseException"));
        } catch (Throwable ignored) {}

        // Sima 2 exceptions
        EXCEPTIONS_CONSIDERED_EVENT.add(GsException.class);
        EXCEPTIONS_CONSIDERED_EVENT.add(GsRuntimeException.class);
    }

    private GsLogger() {
        Logger logger = Logger.getLogger("event-logger");
        if (!logger.hasListeners()) {
            logger = Logger.getLogger("exception-logger");
            if (!logger.hasListeners())
                logger = Logger.getLogger("Q2");
        }
        super.setLogger(logger, LOGGERS_DEFAULT_REALM);
    }

    public static GsLogger getInstance() {
        if (loggerDisabled)
            return new GsLogger();
        if (instance == null) {
            synchronized (GsLogger.class) {
                if (instance == null)
                    instance = new GsLogger();
            }
        }
        return instance;
    }

    private void handleEvent(
            Throwable throwable, Object context, String realm) {
        List<Throwable> causes = new ArrayList<>();
        Throwable cause = throwable;
        do {
            causes.add(cause);
            cause = cause.getCause();
        } while (cause != null);
        boolean exceptionConsideredEvent = false;
        for (Throwable throwableCause : causes) {
            Class<?> throwableClass = throwableCause.getClass();
            do {
                //noinspection SuspiciousMethodCalls
                exceptionConsideredEvent =
                        EXCEPTIONS_CONSIDERED_EVENT.contains(throwableClass);
                throwableClass = throwableClass.getSuperclass();
            } while (throwableClass != null && !exceptionConsideredEvent);
            if (exceptionConsideredEvent)
                break;
        }
        if (exceptionConsideredEvent) {
            GsLogEvent event = new GsLogEvent(realm, context, this);
            event.addMessage(throwable, false); // just log an event concisely
            Logger.log(event);
        }
    }

    private void logIt(
            Throwable throwable, Object context, String realm) {
        handleEvent(throwable, context, realm);
        /*
         * The lines below cause the throwable be printed at the relevant
         * place in main log, though this increases main log file size but
         * makes finding the natural flow of transaction a lot easier
         */
        GsLogEvent exception = new GsLogEvent(realm, context, this);
        exception.addMessage(
                throwable, true);
        appendThrowableToMainLog(exception);
    }

    private void logIt(Throwable throwable) {
        handleEvent(throwable, null, LOGGER_EXCEPTION_TAG_NAME);
        GsLogEvent exception = new GsLogEvent(this, LOGGER_EXCEPTION_TAG_NAME);
        exception.addMessage(
                throwable, true);
        appendThrowableToMainLog(exception);
    }

    public void logIt(GsLogEvent event) {
        //noinspection unchecked
        event.getPayLoad().stream()
                .filter(item -> item instanceof Map.Entry)
                .forEach(item -> {
                    Object mainItem = ((Map.Entry) item).getKey();
                    if (mainItem instanceof Throwable) {
                        handleEvent((Throwable) mainItem,
                                event.getContext(), event.getRealm());
                    }
                });
        appendThrowableToMainLog(event);
    }

    // prologMessageOrTagName for compatibility with old code (should be tag)
    private void logIt(Throwable throwable, String prologMessageOrTagName) {
        boolean consideredMessage = prologMessageOrTagName != null
                && prologMessageOrTagName.length() > 30
                && prologMessageOrTagName.contains(" ");
        // if parameter does not have a space in it, consider it a tag name
        GsLogEvent exception = consideredMessage
                ? new GsLogEvent(this, LOGGER_EXCEPTION_TAG_NAME)
                : new GsLogEvent(this, prologMessageOrTagName);
        if (consideredMessage) // consider it a message (old style code, avoid!)
            exception.addMessage(prologMessageOrTagName);
        else
            handleEvent(throwable, null, prologMessageOrTagName);
        exception.addMessage(
                throwable, true);
        appendThrowableToMainLog(exception);
    }

    private void logIt(String message, ISOMsg isoMessage) {
        LogEvent exception = new LogEvent(this, LOGGER_EXCEPTION_TAG_NAME);
        exception.addMessage(message);
        exception.addMessage(isoMessage);
        appendThrowableToMainLog(exception);
    }

    private void logIt(String message, String realm) {
        LogEvent exception = new LogEvent(this, realm);
        exception.addMessage(message);
        appendThrowableToMainLog(exception);
    }

    public static void log(Throwable throwable) {
        getInstance().logIt(throwable);
    }

    public static void log(String message, String realm) {
        getInstance().logIt(message, realm);
    }

    public static void log(String message) {
        getInstance().logIt(message, LOGGER_EXCEPTION_TAG_NAME);
    }

    public static void log(String message, ISOMsg isoMessage) {
        getInstance().logIt(message, isoMessage);
    }

    // prologueMessageOrTagName for compatibility with old code (should be tag)
    public static void log(
            Throwable throwable, String prologueMessageOrTagName) {
        getInstance().logIt(throwable, prologueMessageOrTagName);
    }

    public static void log(
            Throwable throwable, Object context, String realm) {
        getInstance().logIt(throwable, context, realm);
    }

    public static void log(GsLogEvent logEvent) {
        getInstance().logIt(logEvent);
    }

    public static void log(Throwable throwable, Class errorSite) {
        getInstance().logIt(throwable, errorSite.getSimpleName());
    }

    private void appendThrowableToMainLog(LogEvent exception) {
        Logger.log(exception);
    }

    public static void setLoggerDisabled(boolean loggerDisabled) {
        GsLogger.loggerDisabled = loggerDisabled;
    }
}
