package gs.simulator.core;

import gs.simulator.exception.InvalidConfigurationException;

/**
 * Created by A_Tofigh at 08/02/2024
 */

@FunctionalInterface
public interface ConfigurationUpdateListener<T> {
    void configurationUpdated(T context) throws InvalidConfigurationException;
}
