package gs.simulator.core;

import org.jpos.iso.ISOMsg;

/**
 * Created by A_Tofigh at 08/03/2024
 */
public interface StatsObserver {
    void notify(ISOMsg message);

    void reset();
}
