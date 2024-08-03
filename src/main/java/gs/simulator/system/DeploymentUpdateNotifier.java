package gs.simulator.system;

import com.sun.nio.file.SensitivityWatchEventModifier;
import gs.simulator.core.ConfigurationUpdateListener;
import gs.simulator.logging.GsLogger;
import org.jpos.util.NameRegistrar;

import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.nio.file.StandardWatchEventKinds.*;

/**
 * Created by A_Tofigh at 08/02/2024
 */
public class DeploymentUpdateNotifier {
    private static final String THIS_CLASS_NAME = "deployment-update-notifier";

    private static DeploymentUpdateNotifier instance;

    private Map<Path, List<ConfigurationUpdateListener<Path>>>
            pathUpdateListeners = new HashMap<>();
    private Thread watcherThread;
    private boolean keepWatching;
    private WatchService watchService;
    private Map<Path, WatchKey> watchedDirsKeys = new HashMap<>();
    private Map<Path, Instant> lastNotificationTimestamps = new HashMap<>();

    private DeploymentUpdateNotifier() throws IOException {
        watchService = FileSystems.getDefault().newWatchService();
        keepWatching = true;
        watcherThread = new Thread(() -> {
            while (keepWatching) {
                WatchKey watchKey = null;
                StringBuilder activitiesBuilder = new StringBuilder();
                try {
                    watchKey = watchService.take();
                    for (WatchEvent<?> event : watchKey.pollEvents()) {
                        @SuppressWarnings("unchecked")
                        WatchEvent<Path> pathEvent = (WatchEvent<Path>) event;
                        Path changedItemPath = pathEvent.context();
                        Path parentDir = (Path) watchKey.watchable();
                        Path changedItemAbsolutePath =
                                parentDir.resolve(changedItemPath);
                        // Prevent multiple successive notifications
                        Instant now = Instant.now();
                        Instant lastTimestamp = lastNotificationTimestamps.get(
                                changedItemAbsolutePath);
                        if (lastTimestamp != null) {
                            if (lastTimestamp.until(now, ChronoUnit.SECONDS)
                                    < 1)
                                continue;
                            else
                                lastNotificationTimestamps.put(
                                        changedItemAbsolutePath, now);
                        } else {
                            lastNotificationTimestamps.put(
                                    changedItemAbsolutePath, now);
                        }
                        if (activitiesBuilder.length() > 0)
                            activitiesBuilder.append("\n");
                        activitiesBuilder
                                .append("Notified of a filesystem ")
                                .append("change in path: ")
                                .append(changedItemPath);
                        for (Map.Entry<Path,
                                List<ConfigurationUpdateListener<Path>>> pul
                                : pathUpdateListeners.entrySet()) {
                            // Guard against unnecessary updates to listeners
                            // Take into account parent-child relationship
                            /*Path changedItemAbsolutePath =
                                    changedItemPath.toAbsolutePath();*/
                            // Crappy Java Watch API, What were they smoking?
                            Path registeredAbsolutePath =
                                    pul.getKey().toAbsolutePath();
                            if ((registeredAbsolutePath.toFile().isFile()
                                    && changedItemAbsolutePath.equals(
                                    registeredAbsolutePath)) ||
                                    (registeredAbsolutePath.toFile()
                                            .isDirectory()
                                            && changedItemAbsolutePath
                                            .startsWith(
                                                    registeredAbsolutePath))) {
                                for (ConfigurationUpdateListener<Path> cul
                                        : pul.getValue()) {
                                    String path = pul.getKey().toString()
                                            .isEmpty() ? "."
                                            : pul.getKey().toString();
                                    activitiesBuilder
                                            .append("\nNotified dependent ")
                                            .append("module of deployment ")
                                            .append("configuration changes: ")
                                            .append(cul).append(" on '")
                                            .append(path).append("'");
                                    try {
                                        cul.configurationUpdated(
                                                changedItemAbsolutePath);
                                    } catch (Exception e) {
                                        if (NameRegistrar.getIfExists(
                                                "main-logger") != null)
                                            GsLogger.log(
                                                    e, cul, THIS_CLASS_NAME);
                                        /*else
                                            e.printStackTrace();*/
                                    }
                                }
                            }
                        }
                    }
                } catch (InterruptedException e) {
                    if (NameRegistrar.getIfExists("main-logger") != null)
                        GsLogger.log(e, THIS_CLASS_NAME);
                    /*else
                        e.printStackTrace();*/
                    return;
                } finally {
                    if (watchKey != null) {
                        // Don't forget to reset the key for next events
                        if (!watchKey.reset()) {
                            keepWatching = false;
                            activitiesBuilder
                                    .append("\nForced to shut down deployment ")
                                    .append("configuration update ")
                                    .append("notification due to an unknown ")
                                    .append("reason: resetting watch key ")
                                    .append("failed!");
                        }
                    }
                    if (activitiesBuilder.length() > 0) {
                        if (NameRegistrar.getIfExists("main-logger") != null)
                            GsLogger.log(activitiesBuilder.toString(),
                                    THIS_CLASS_NAME);
                        /*else
                            System.out.println(activitiesBuilder.toString());*/
                    }
                }
            }
        });
        watcherThread.setName("deployment-update-notifier");
        watcherThread.setDaemon(true);
        watcherThread.start();
    }

    public static DeploymentUpdateNotifier getInstance() throws IOException {
        if (instance != null)
            return instance;
        synchronized (DeploymentUpdateNotifier.class) {
            if (instance != null)
                return instance;
            instance = new DeploymentUpdateNotifier();
        }
        return instance;
    }

    /**
     * Starts watching on the directory represented by the path and registers
     * the given listener to be notified when a change detected on path. If
     * another client already has registered a listener on the directory then
     * just add the provided listener to the list of interested listeners for
     * change notifications.
     *
     * @param interestedPath the path to watch changes on. If the path
     *                       represents a directory then the listener would be
     *                       notified when every child (dir or file) changes
     *                       (including additions and removals) but if the path
     *                       represents a file then only changes to that file
     *                       would notify the listener.
     * @param listener       the callback method to be called when a change detected
     * @throws IOException if cannot watch notifications on the given path
     */
    public void watch(
            Path interestedPath, ConfigurationUpdateListener<Path> listener)
            throws IOException {
        /**
         * There is a problem (feature?) identifying parent-child relation
         * when using . as current directory in Path API and we must use ""
         */
        if (".".equals(interestedPath.toString()))
            interestedPath = Paths.get("");
        interestedPath = interestedPath.toAbsolutePath();
        Path interestedDir = interestedPath;
        if (interestedPath.toFile().isFile())
            interestedDir = interestedPath.getParent();
        if (watchedDirsKeys.get(interestedDir) == null) {
            WatchKey watchedDirKey = interestedDir.register(
                    watchService, new WatchEvent.Kind[]{
                            ENTRY_CREATE, ENTRY_MODIFY, ENTRY_DELETE},
                    SensitivityWatchEventModifier.LOW);
            watchedDirsKeys.put(interestedDir, watchedDirKey);
        }
        if (pathUpdateListeners.get(interestedPath) == null)
            pathUpdateListeners.put(interestedPath, new ArrayList<>());
        pathUpdateListeners.get(interestedPath).add(listener);
    }

    public void watch(
            String interestedPath, ConfigurationUpdateListener<Path> listener)
            throws IOException {
        watch(Paths.get(interestedPath), listener);
    }

    public void watch(
            File interestedPath, ConfigurationUpdateListener<Path> listener)
            throws IOException {
        watch(interestedPath.toPath(), listener);
    }

    @SuppressWarnings("unused")
    public void watchAppRootDir(ConfigurationUpdateListener<Path> listener)
            throws IOException {
        watch(Paths.get(""), listener);
    }

    /**
     * Removes the given callback listener from the list of notified modules.
     * If there is no such listener previously registered on this path, nothing
     * would be done.
     *
     * @param interestedPath the path to stop watching on
     * @param listener       the callback listener to be removed from notified
     *                       modules list (others may exist still)
     * @throws IOException if cannot stop watching on the given path
     */
    public void stopWatch(
            Path interestedPath, ConfigurationUpdateListener<Path> listener)
            throws IOException {
        List<ConfigurationUpdateListener<Path>>
                listenersOnThisPath = pathUpdateListeners.get(interestedPath);
        if (listenersOnThisPath == null)
            return;
        listenersOnThisPath.remove(listener);
        if (listenersOnThisPath.isEmpty()) {
            WatchKey watchedDirKey = watchedDirsKeys.get(interestedPath);
            if (watchedDirKey != null)
                watchedDirKey.cancel();
            watchedDirsKeys.remove(interestedPath);
        }
    }

    public void stopWatch(
            String interestedPath, ConfigurationUpdateListener<Path> listener)
            throws IOException {
        stopWatch(Paths.get(interestedPath), listener);
    }

    public void stopWatch(
            File interestedPath, ConfigurationUpdateListener<Path> listener)
            throws IOException {
        stopWatch(interestedPath.toPath(), listener);
    }

    @SuppressWarnings("unused")
    public void stopOnAppRootDir(ConfigurationUpdateListener<Path> listener)
            throws IOException {
        stopWatch(Paths.get(""), listener);
    }

    @SuppressWarnings("unused")
    public void stopAll() throws IOException {
        keepWatching = false;
        for (Map.Entry<Path, WatchKey> watchKeys : watchedDirsKeys.entrySet()) {
            try {
                watchKeys.getValue().cancel();
            } catch (Exception e) {
                GsLogger.log(e, watchKeys.getKey(), THIS_CLASS_NAME);
            }
        }
        watchedDirsKeys.clear();
        watcherThread.interrupt();
        try {
            pathUpdateListeners.clear();
        } catch (Exception e) {
            GsLogger.log(e, THIS_CLASS_NAME);
        }
    }

    public void destroy() throws IOException {
        // TODO hold instance state so that after this call never allow to
        // start() it again (state is an enum with members like { INITIAL,
        // STARTED (aka IN_SERVICE or RUNNING), STOPPED, DESTROYED }
        watchService.close();
    }
}
