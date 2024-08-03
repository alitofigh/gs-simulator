package gs;

import gs.simulator.exception.InvalidCommandException;
import gs.simulator.system.DeploymentUpdateNotifier;
import org.jpos.iso.*;
import gs.simulator.util.ParseUtil;
import org.jpos.util.LogEvent;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

import static gs.simulator.util.SecurityUtil.decryptCredentialAllParamsPredefined;
import static gs.simulator.util.StringUtil.fixWidth;
import static gs.simulator.util.StringUtil.fixWidthSpacePad;

/**
 * Created by A_Tofigh at 08/02/2024
 */
public class PTSimulator {

    private final static String CONFIGURATION_FILE_NAME = "simulator-config.properties";
    private static final String DEFAULT_CHANNEL = "org.jpos.iso.channel.ASCIIChannel";
    private static boolean exit = false;
    private boolean dumpStackTrace = false;
    private String commandLine;
    private String[] commandAndArgs;
    private int unconsumedArgIndex;
    private List<ISOMsg> isoMessages = new ArrayList<>();
    private int currentMessageIndex;
    private Properties properties;
    private ISOPackager messagePackager;
    private String hostAddress;
    private int hostPort;
    private int connectionTimeout;
    private int responseTimeout;
    private ISOServer isoServer;
    private String dumpFormat = "hex";
    private String bindChannel = DEFAULT_CHANNEL;
    private Map<String, String> keys = new HashMap<>();

    public static void main(String[] args) {
        PTSimulator clientSimulator = new PTSimulator();
        try {
            clientSimulator.loadRequiredData();
            clientSimulator.loadKeys();
            BufferedReader bufferedReader =
                    new BufferedReader(new InputStreamReader(System.in));
            System.out.println("Please enter your command");

            do {
                String commandLine;
                try {
                    commandLine = bufferedReader.readLine();
                    if (commandLine == null)
                        break;
                    if (commandLine.isEmpty())
                        continue;
                    clientSimulator.setCommandLine(commandLine);
                    clientSimulator.execute();
                    if (!exit)
                        log("\n--------------------------------------------------");
                } catch (Exception e) {
                    System.out.println(e.getMessage());
                    if (!exit)
                        log("\n--------------------------------------------------");
                }
            } while (!exit);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    public PTSimulator() {
        try {
            try {
                DeploymentUpdateNotifier.getInstance().watch(
                        CONFIGURATION_FILE_NAME, path -> {
                            try {
                                updateConfiguration();
                            } catch (Exception e) {
                                log(e, dumpStackTrace);
                            }
                        });
            } finally {
                try {
                    DeploymentUpdateNotifier.getInstance().watch(
                            "terminal-keys.properties", path -> {
                                try {
                                    updateConfiguration();
                                } catch (Exception e) {
                                    log(e, dumpStackTrace);
                                }
                            });
                } finally {
                    updateConfiguration();
                }
            }
        } catch (Exception e) {
            log(e, dumpStackTrace);
        }
    }

    public void execute() throws Exception {
        if (commandLine == null)
            throw new IllegalArgumentException("Null command line encountered");
        commandAndArgs =
                ParseUtil.splitTokens(commandLine).toArray(new String[0]);
        String command = commandAndArgs[0].trim();
        unconsumedArgIndex = 1;
        switch (command) {
            case "make":
            case "m":
                break;
            case "list":
            case "l":
                list();
                break;
            case "communicate":
            case "com":
                communicate();
                break;
            default:
                throw new InvalidCommandException(
                        String.format("No such command: %s", command));
        }
    }

    private void communicate() throws Exception {
        ISOMsg targetIsoMessage = getIsoMessage(currentMessageIndex);
        communicateSyncSingleMessage(targetIsoMessage);
    }

    private void communicateWithConnectedPeer(ISOMsg isoMessage)
            throws Exception {
        ClientChannel channel =
                (ClientChannel) isoServer.getLastConnectedISOChannel();
        isoMessage.setPackager(messagePackager);
        channel.send(isoMessage);
        log(isoMessage);
        //notifyRequestObservers(isoMessage);
        AtomicBoolean receiveDone = new AtomicBoolean(false);
        Thread receiverThread = new Thread(() -> {
            try {
                ((BaseChannel) channel).setTimeout(responseTimeout);
                ISOMsg response = channel.receive();
                if (response != null) {
                    log(response);
                    //notifyResponseObservers(response);
                } else {
                    log("No response received (timeout)");
                }
            } catch (Exception e) {
                log(e, dumpStackTrace);
            } finally {
                receiveDone.set(true);
            }
        });
        receiverThread.start();
        while (!receiveDone.get())
            ISOUtil.sleep(500);
    }

    private void communicateSyncSingleMessage(ISOMsg isoMessage)
            throws Exception {
        ClientChannel channel = instantiateClientChannel(
                hostAddress, hostPort, messagePackager);
        /*if (secureSocket)
            ((BaseChannel) channel).setSocketFactory(
                    makeSunJsseSocketFactory());*/
        ((BaseChannel) channel).setTimeout(connectionTimeout);
        channel.connect();
        isoMessage.setPackager(messagePackager);
        channel.send(isoMessage);
        log(isoMessage);
        //notifyRequestObservers(isoMessage);
        AtomicBoolean receiveDone = new AtomicBoolean(false);
        Thread receiverThread = new Thread(() -> {
            try {
                ((BaseChannel) channel).setTimeout(responseTimeout);
                ISOMsg response = channel.receive();
                if (response != null) {
                    log(response);
                    //notifyResponseObservers(response);
                } else {
                    log("No response received (timeout)");
                }
            } catch (Exception e) {
                log(e, dumpStackTrace);
            } finally {
                receiveDone.set(true);
                try {
                    channel.disconnect();
                } catch (IOException e) {
                    log(e, dumpStackTrace);
                }
            }
            receiveDone.set(true);
        });
        receiverThread.start();
        while (!receiveDone.get())
            ISOUtil.sleep(500);
    }

    private ClientChannel instantiateClientChannel(
            String address, int port, ISOPackager packager)
            throws ClassNotFoundException, IllegalAccessException,
            InstantiationException {
        ClientChannel clientChannel =
                (ClientChannel) Class.forName(bindChannel).newInstance();
        clientChannel.setHost(address, port);
        clientChannel.setPackager(packager);
        return clientChannel;
    }

    private ISOServer instantiateIsoServer(
            String address, int port)
            throws ClassNotFoundException, InstantiationException,
            IllegalAccessException, UnknownHostException {
        ServerChannel serverChannel =
                instantiateServerChannel();
        // TODO read thread pool size of server channel from config
        //if (isoServer == null) {
        //serverChannel.setTimeout(responseTimeout);
        ISOServer isoServer = new ISOServer(port, serverChannel, null);
        //isoServer.bindAddr = InetAddress.getByName(address);
        return isoServer;
    }

    private ServerChannel instantiateServerChannel()
            throws ClassNotFoundException, IllegalAccessException,
            InstantiationException {
        ServerChannel serverChannel =
                (ServerChannel) Class.forName(bindChannel).newInstance();
        serverChannel.setPackager(messagePackager);
        return serverChannel;
        /*return (ServerChannel)
                Class.forName(bindChannel).getConstructor(new Class[] {
                        ISOPackager.class })
                        .newInstance(Class.forName(packagerFqn).newInstance());*/
    }

    /*private void notifyRequestObservers(ISOMsg isoMessage) {
        try {
            for (StatsObserver requestObserver : requestObservers) {
                //log("Notifying request observer: " + requestObserver);
                requestObserver.notify(isoMessage);
            }
        } catch (Exception e) {
            log(e, dumpStackTrace);
        }
    }

    private void notifyResponseObservers(ISOMsg isoMessage) {
        try {
            for (StatsObserver responseObserver : responseObservers) {
                //log("Notifying response observer: " + responseObserver);
                responseObserver.notify(isoMessage);
            }
        } catch (Exception e) {
            log(e, dumpStackTrace);
        }
    }*/

    public void setCommandLine(String commandLine) {
        if (commandLine == null)
            throw new IllegalArgumentException("Null command line encountered");
        this.commandLine = commandLine;
    }

    public void make() throws ClassNotFoundException, InstantiationException, IllegalAccessException {
        ISOMsg isoMessage = new ISOMsg();
        isoMessage.setPackager(messagePackager);
    }

    public void setCurrentMessageIndex(int currentMessageIndex) {
        if (currentMessageIndex < 0
                || currentMessageIndex >= isoMessages.size())
            throw new IllegalArgumentException(String.format(
                    "Specified message index is out of bounds; invalid index: "
                            + "%d, acceptable range: %d-%d"
                            + currentMessageIndex, 0, isoMessages.size()));
        this.currentMessageIndex = currentMessageIndex;
    }

    private synchronized void log(ISOMsg isoMessage) {
        LogEvent logEvent = new LogEvent("client-simulator", isoMessage);
        try {
            logEvent.addMessage(dumpProperFormat(isoMessage));
        } catch (ISOException e) {
            logEvent.addMessage(e.getMessage());
        }
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        PrintStream printStream = new PrintStream(outputStream);
        logEvent.dump(printStream, "");
        log(outputStream.toString());
    }

    private String dumpProperFormat(ISOMsg isoMessage) throws ISOException {
        byte[] messageBytes = isoMessage.pack();
        return "hex".equalsIgnoreCase(dumpFormat)
                ? ISOUtil.hexString(messageBytes)
                : "ascii".equalsIgnoreCase(dumpFormat)
                ? ISOUtil.dumpString(messageBytes)
                : "bytes".equalsIgnoreCase(dumpFormat)
                ? Arrays.toString(messageBytes)
                : ISOUtil.hexdump(messageBytes);
    }

    private void listCurrent() throws InvalidCommandException {
        ISOMsg currentMessage = getIsoMessage(currentMessageIndex);
        StringBuilder messageData = new StringBuilder();
        messageData.append(" * ").append(fixWidthSpacePad(
                "" + currentMessageIndex, 2)).append(") ");
        if (unconsumedArgIndex == commandAndArgs.length) {
            messageData.append(makeIsoMessageString(currentMessage));
        } else {
            for (; unconsumedArgIndex < commandAndArgs.length;
                 unconsumedArgIndex++) {
                String option = commandAndArgs[unconsumedArgIndex].trim();
                int fieldNo = parseField(option);
                unconsumedArgIndex++;
                if (currentMessage.hasField(fieldNo))
                    messageData.append(fieldNo).append(": ")
                            .append(currentMessage.getString(fieldNo))
                            .append("; ");
            }
            if (messageData.length() > "; ".length())
                messageData.delete(messageData.length() - "; ".length(),
                        messageData.length());
        }
        log(messageData.toString());
    }

    private int parseField(String option, int argIndex)
            throws InvalidCommandException {
        int fieldNo = -1;
        if (option.startsWith("-")) {
            option = option.substring(1);
            try {
                fieldNo = Integer.parseInt(option);
            } catch (Exception e) {
                throw new InvalidCommandException(String.format(
                        "Expected numeric option as message field but got "
                                + "'%s'", commandAndArgs[argIndex]));
            }
        } else {
            // Option is a command line argument which starts with - or --
            throw new InvalidCommandException(String.format(
                    "Expected an option but got the argument '%s'",
                    commandAndArgs[argIndex]));
        }
        return fieldNo;
    }

    private int parseField(String option) throws InvalidCommandException {
        return parseField(option, unconsumedArgIndex);
    }

    private ISOMsg getIsoMessage(int index) {
        if (index < 0 || index >= isoMessages.size())
            throw new IllegalArgumentException(String.format(
                    "Specified message index is out of bounds; invalid index: "
                            + "%d, acceptable range: %d-%d",
                    index, 0, isoMessages.size()));
        return isoMessages.get(index);
    }

    private void list() throws InvalidCommandException {
        if (!isAnyArgProvided()) {
            listAll();
            return;
        }
        String nextOption = commandAndArgs[unconsumedArgIndex].trim();
        if (!nextOption.startsWith("-"))
            setCurrentMessageIndex(parseMessageId());
        ISOMsg currentMessage = getIsoMessage(currentMessageIndex);
        StringBuilder messageData = new StringBuilder();
        if (!isAnyArgProvided()) {
            messageData.append(makeIsoMessageString(currentMessage));
        } else {
            for (; isAnyArgProvided(); unconsumedArgIndex++) {
                nextOption = commandAndArgs[unconsumedArgIndex].trim();
                int fieldNo = parseField(nextOption);
                unconsumedArgIndex++;
                if (currentMessage.hasField(fieldNo))
                    messageData.append(fieldNo).append(": ")
                            .append(currentMessage.getString(fieldNo))
                            .append("; ");
            }
            if (messageData.length() > "; ".length())
                messageData.delete(messageData.length() - "; ".length(),
                        messageData.length());
        }
        log(messageData.toString());
    }

    private boolean isAnyArgProvided() {
        return unconsumedArgIndex < commandAndArgs.length;
    }

    private int parseMessageId() throws InvalidCommandException {
        int messageId = parseNextNumericArg("message-id");
        if (messageId < 0 || messageId >= isoMessages.size())
            throw new InvalidCommandException(String.format(
                    "Specified message id is out of bounds; invalid message "
                            + "id: %d", messageId));
        return messageId;
    }

    private int parseNextNumericArg(String option)
            throws InvalidCommandException {
        ensureArgProvided(option);
        try {
            return Integer.parseInt(commandAndArgs[unconsumedArgIndex].trim());
        } catch (Exception e) {
            throw new InvalidCommandException(String.format(
                    "Expected numeric argument as <" + option
                            + "> but got '%s'",
                    commandAndArgs[unconsumedArgIndex]));
        } finally {
            unconsumedArgIndex++;
        }
    }

    private void ensureArgProvided(String option)
            throws InvalidCommandException {
        if (!isAnyArgProvided())
            throw new InvalidCommandException(String.format(
                    "Expected an argument for the value of option <%s> "
                            + "but reached end of line", option));
    }


    private void listAll() {
        //isoMessages.forEach(isoMessage -> log(makeIsoMessageString(isoMessage)));
        for (int i = 0; i < isoMessages.size(); i++) {
            String messageDump = " ";
            if (currentMessageIndex == i)
                messageDump += "* ";
            else
                messageDump += " ";
            messageDump += fixWidth("" + i, 2, ' ', true)
                    + ") " + makeIsoMessageString(isoMessages.get(i));
            log(messageDump);
        }
    }

    private String makeIsoMessageString(ISOMsg isoMessage) {
        StringBuilder isoMessageDump = new StringBuilder();
        for (int i = 0; i <= isoMessage.getMaxField(); i++) {
            if (isoMessage.hasField(i))
                isoMessageDump.append(i).append(": ")
                        .append(isoMessage.getString(i)).append("; ");
            else if (i == 1 && isoMessage.getHeader() != null)
                isoMessageDump.append(i).append(": ")
                        .append(ISOUtil.hexString(isoMessage.getHeader()))
                        .append("; ");
        }
        if (isoMessageDump.length() > "; ".length())
            isoMessageDump.delete(isoMessageDump.length() - "; ".length(),
                    isoMessageDump.length());
        return isoMessageDump.toString() + "\n";
    }

    private static void log(String message) {
           /* synchronized (gs.PTSimulator.class) {
                //noinspection deprecation
                Logger.getLogger("ResultConsoleLogger")
                        .log(Priority.DEBUG, message);
        }*/
        System.out.println(message);
    }

    private static void log(Throwable e, boolean dumpStackTrace) {
        StringBuilder message = new StringBuilder();
        if (dumpStackTrace) {
            StringWriter stringWriter = new StringWriter();
            PrintWriter printWriter = new PrintWriter(stringWriter);
            e.printStackTrace(printWriter);
            message = new StringBuilder(stringWriter.toString());
        } else {
            Throwable cause = e;
            do {
                message.append(cause.getClass().getSimpleName())
                        .append(": ").append(cause.getMessage()).append("\n");
                cause = cause.getCause();
            } while (cause != null);
        }
        log(message.toString());
    }

    private void loadRequiredData() throws IOException, ISOException {
        Properties prop = new Properties();
        InputStream inputStream = Files.newInputStream(Paths.get("sample-messages.properties"));
        prop.load(inputStream);
        inputStream.close();
        if (prop.isEmpty())
            return;
        prop.stringPropertyNames().forEach(propertyKey -> {
            ISOMsg isoMsg = new ISOMsg();
            isoMsg.setPackager(messagePackager);
            String msg = prop.getProperty(propertyKey);
            try {
                isoMsg.unpack(msg.getBytes(StandardCharsets.UTF_8));
            } catch (ISOException e) {
                throw new RuntimeException(e);
            }
            isoMessages.add(isoMsg);
        });
    }

    private void loadKeys() throws IOException {
        Properties prop = new Properties();
        InputStream inputStream = Files.newInputStream(Paths.get("terminal-key.properties"));
        prop.load(inputStream);
        if (prop.isEmpty())
            return;
        prop.stringPropertyNames().forEach(propertyKey -> {
            String key;
            try {
                key = decryptCredentialAllParamsPredefined(prop.getProperty(propertyKey));
            } catch (NoSuchPaddingException e) {
                throw new RuntimeException(e);
            } catch (InvalidKeyException e) {
                throw new RuntimeException(e);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            } catch (IOException e) {
                throw new RuntimeException(e);
            } catch (BadPaddingException e) {
                throw new RuntimeException(e);
            } catch (IllegalBlockSizeException e) {
                throw new RuntimeException(e);
            } catch (InvalidAlgorithmParameterException e) {
                throw new RuntimeException(e);
            } catch (InvalidKeySpecException e) {
                throw new RuntimeException(e);
            }
            keys.put(propertyKey, key);
        });
    }


    private void updateConfiguration()
            throws IOException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        properties = new Properties();
        InputStream inputStream = new FileInputStream(CONFIGURATION_FILE_NAME);
        properties.load(inputStream);
        inputStream.close();
        if (properties.isEmpty())
            return;
        hostAddress = properties.getProperty("ip");
        hostPort = Integer.parseInt(properties.getProperty("port"));
        messagePackager = (ISOPackager) Class.forName(
                properties.getProperty("packager", "gs.simulator.packager.GsPackager"))
                .newInstance();
        connectionTimeout = Integer.parseInt(properties.getProperty("connect-timeout"));
        responseTimeout = Integer.parseInt(properties.getProperty("response-timeout"));
        bindChannel = properties.getProperty("bind-channel");

    }
}
