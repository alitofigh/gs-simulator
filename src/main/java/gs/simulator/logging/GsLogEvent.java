package gs.simulator.logging;

import org.jpos.util.LogEvent;
import org.jpos.util.LogSource;
import org.jpos.util.Loggeable;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.sql.SQLException;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.logging.Level;

/**
 * Created by A_Tofigh at 07/17/2024
 */
public class GsLogEvent extends LogEvent {
    private LogSource source;
    private String tag;
    private List<Object> payLoad;
    private long createdAt;
    private long dumpedAt;
    //@RSh
    private ThreadLocal<DateTimeFormatter> threadDateTimeFormatter =
            ThreadLocal.withInitial(() ->
                    DateTimeFormatter.ofPattern("yyyy.MM.dd HH:mm:ss.SSS")
                            .withZone(ZoneId.systemDefault()));
    //@RSh: To support logging context (transaction) data in header of log entry
    private Object context;
    private Level logLevel;

    public GsLogEvent (String tag) {
        super();
        this.tag = tag;
        createdAt = System.currentTimeMillis();
        this.payLoad = new ArrayList<>();
    }

    public GsLogEvent () {
        this ("info");
    }
    public GsLogEvent (String tag, Object msg) {
        this (tag);
        addMessage(msg);
    }
    public GsLogEvent (LogSource source, String tag) {
        this (tag);
        this.source  = source;
    }
    public GsLogEvent (LogSource source, String tag, Object msg) {
        this (tag);
        this.source  = source;
        addMessage(msg);
    }

    //@RSh
    public GsLogEvent (String realm, Object context, LogSource source) {
        this(realm);
        this.context = context;
        this.source  = source;
    }

    //@RSh
    public GsLogEvent (
            String realm, Object context, LogSource source, String message) {
        this(realm);
        this.context = context;
        this.source  = source;
        addMessage(message);
    }

    //@RSh
    public GsLogEvent (
            String realm, Object context, LogSource source,
            String message, Level atLevel) {
        this(realm);
        this.context = context;
        this.source  = source;
        this.logLevel = atLevel;
        addMessage(message, atLevel);
    }

    public Object getContext() {
        return context;
    }

    public String getTag() {
        return tag;
    }
    public void addMessage (Object msg) {
        payLoad.add (msg);
    }
    public void addMessage (String tagname, String message) {
        payLoad.add ("<"+tagname+">"+message+"</"+tagname+">");
    }

    //@RSh
    @SuppressWarnings("CopyConstructorMissesField")
    public GsLogEvent(LogEvent copy) {
        this.source = copy.getSource();
        this.tag = copy.getTag();
        this.payLoad = copy.getPayLoad();
    }

    //@RSh
    public void addMessage(Throwable throwable, boolean dumpStackTrace) {
        payLoad.add(new AbstractMap.SimpleEntry<>(throwable, dumpStackTrace));
    }

    //@RSh
    public void addMessage(String message, Level atLevel) {
        payLoad.add(new AbstractMap.SimpleEntry<>(message, atLevel));
    }

    //@RSh
    public void addMessage(Throwable throwable, Level atLevel) {
        payLoad.add(new AbstractMap.SimpleEntry<>(throwable, atLevel));
    }

    //@RSh
    public void addMessage(List<?> messages) {
        payLoad.addAll(messages);
    }

    public LogSource getSource() {
        return source;
    }
    public void setSource(LogSource source) {
        this.source = source;
    }
    protected String dumpHeader (PrintStream p, String indent) {
        if (dumpedAt == 0L)
            dumpedAt = System.currentTimeMillis();
        Date date = new Date (dumpedAt);
        StringBuilder sb = new StringBuilder(indent);
        sb.append ("<log realm=\"");
        //@RSh: set realm as the source class to remove tag (keep backward compatibility)
        String realm = getRealm();
        String trueRealm = realm == null || realm.isEmpty()
                ? tag == null ? "" : tag
                : tag == null || tag.isEmpty() ? realm
                : realm.equalsIgnoreCase(tag) ? realm : realm + "#" + tag;
        sb.append (trueRealm);
        sb.append ( "\" at=\"");
        sb.append(threadDateTimeFormatter.get().format(date.toInstant()));
        if (dumpedAt != createdAt)
            sb.append("\" lifespan=\"")
                    .append(dumpedAt - createdAt)
                    .append("ms");
        sb.append ("\">");
        p.println(sb.toString());
        return indent + "  ";
    }
    protected void dumpTrailer (PrintStream p, String indent) {
        p.println (indent + "</log>");
    }
    public void dump (PrintStream p, String outer) {
        String newIndent = dumpHeader (p, outer);
        for (Object o : payLoad) {
            if (o instanceof String) {
                //@RSh: adjusting indent for each line
                o = indentLines((String) o, newIndent);
                p.println(newIndent + o);
            } else if (o instanceof Loggeable) {
                ((Loggeable) o).dump(p, newIndent);
            } else if (o instanceof SQLException) {
                SQLException e = (SQLException) o;
                p.println(newIndent + "<SQLException>"
                        + e.getMessage() + "</SQLException>");
                p.println(newIndent + "<SQLState>"
                        + e.getSQLState() + "</SQLState>");
                p.println(newIndent + "<VendorError>"
                        + e.getErrorCode() + "</VendorError>");
                ((Throwable) o).printStackTrace(p);
            } else if (o instanceof Throwable) {
                //@RSh
                /*p.println(newIndent + "<exception name=\""
                        + ((Throwable) o).getMessage() + "\">");*/
                String description = ((Throwable) o).getMessage();
                p.println(newIndent + "<exception name=\""
                        + o.getClass().getSimpleName()
                        + (description != null ? "\" description=\""
                        + indentLines(description, newIndent) : "") + "\">");
                p.print(newIndent);
                ((Throwable) o).printStackTrace(p);
                p.println(newIndent + "</exception>");
            }
            //@RSh: to support logging context data with exceptions and info
            else if (o instanceof Map.Entry) {
                Map.Entry logEntry = (Map.Entry) o;
                if (logEntry.getValue() instanceof Level) {
                    // TODO only log at appropriate level not like below
                    p.println(newIndent + logEntry.getKey());
                } else if (logEntry.getKey() instanceof Throwable) {
                    Throwable throwable = (Throwable) logEntry.getKey();
                    String description = throwable.getMessage();
                    p.print(newIndent + "<exception name=\""
                            + throwable.getClass().getSimpleName()
                            + (description != null ? "\" description=\""
                            + indentLines(throwable.getMessage(), newIndent)
                            : ""));
                    boolean dumpStackTrace = (Boolean) logEntry.getValue();
                    if (dumpStackTrace) {
                        p.println("\">");
                        p.print(newIndent);
                        throwable.printStackTrace(p);
                        p.println(newIndent + "</exception>");
                    } else {
                        throwable = throwable.getCause();
                        if (throwable == null) {
                            p.println("\" />");
                        } else {
                            p.println("\">");
                            StringBuilder causesIndented =
                                    new StringBuilder(newIndent);
                            while (throwable != null) {
                                causesIndented.append("  ");
                                description = throwable.getMessage();
                                p.println(causesIndented + "<cause name=\""
                                        + throwable.getClass().getSimpleName()
                                        + (description != null
                                        ? "\" description=\""
                                        + indentLines(description, newIndent)
                                        : "") + "\" />");
                                throwable = throwable.getCause();
                            }
                            p.println(newIndent + "</exception>");
                        }
                    }
                } else {
                    Object contextData = logEntry.getKey();
                    Object logData = logEntry.getValue();
                    if (logData instanceof Map.Entry) {
                        Map.Entry throwableEntry = (Map.Entry) logData;
                        Throwable throwable =
                                (Throwable) throwableEntry.getKey();
                        String description = throwable.getMessage();
                        p.print(newIndent + "<exception context=\""
                                + contextData + "\" name=\""
                                + throwable.getClass().getSimpleName()
                                + (description != null ? "\" description=\""
                                + indentLines(description, newIndent) : ""));
                        boolean dumpStackTrace =
                                (Boolean) throwableEntry.getValue();
                        if (dumpStackTrace) {
                            p.println("\">");
                            p.print(newIndent);
                            throwable.printStackTrace(p);
                            p.println(newIndent + "</exception>");
                        } else {
                            p.println("\" />");
                        }
                    } else {
                        p.println(newIndent + logData
                                + " *** " + contextData);
                    }
                }
            } else if (o instanceof Object[]) {
                Object[] oa = (Object[]) o;
                p.print(newIndent + "[");
                for (int j = 0; j < oa.length; j++) {
                    if (j > 0)
                        p.print(",");
                    p.print(oa[j].toString());
                }
                p.println("]");
            }
        }
        //@RSh: remove end tag because it removed completely
        /*if (tag != null)
            p.println (indent + "</" + tag + ">");*/
        dumpTrailer(p, outer);
    }

    public String getRealm() {
        //@ manipulated at dml
        String realm = source != null ? source.getRealm() : null;
        return realm != null ? realm.replaceAll("jpos", "dml") : "";
    }
    public List getPayLoad() {
        return payLoad;
    }
    public String toString() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream p = new PrintStream (baos);
        dump (p, "");
        return baos.toString();
    }

    //@RSh
    public Level getLevel() {
        return logLevel;
    }

    private String indentLines(String message, String newIndent) {
        if (message == null)
            return null;
        //@RSh: Let XML tags (which start with '<') be indented as before
        if (!message.startsWith("<"))
            return message.replaceAll("\n", "\n" + newIndent);
        return message;
    }
}
