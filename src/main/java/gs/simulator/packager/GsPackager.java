package gs.simulator.packager;

import org.jpos.iso.*;

/**
 * Created by A_Tofigh at 7/14/2024
 */

public class GsPackager extends ISOBasePackager {
    protected ISOFieldPackager fld[] = {
            /*000*/ new IFA_NUMERIC(4, "Message Type Indicator"),
            /*001*/ new IFA_BITMAP(16, "Bitmap"),
            /*002*/ new IF_CHAR(4, "gs_id"),
            /*003*/ new IF_CHAR(2, "pt_id"),
            /*004*/ new IF_CHAR(6, "traceNo"),
            /*005*/ new IF_CHAR(14, "transaction-Date-time"),
            /*006*/ new IF_CHAR(2, "zone_id"),
            /*007*/ new IF_CHAR(4, "city_id"),
            /*008*/ new IF_CHAR(5, "gs_code"),
            /*009*/ new IFA_LLCHAR(20, "contact_telephone"),
            /*010*/ new IFA_LLCHAR(20, "telephone1"),
            /*011*/ new IFA_LLCHAR(20, "fax"),
            /*012*/ new IFA_LLCHAR(99, "shift_no"),
            /*013*/ new IFA_LLCHAR(99, "daily_no"),
            /*014*/ new IFA_LLCHAR(99, "fuel_ttc"),
            /*015*/ new IFA_LLCHAR(99, "epurse_tcc"),
            /*016*/ new IFA_LLCHAR(99, "fuel_time"),
            /*017*/ new IFA_LLCHAR(99, "epurse_time"),
            /*018*/ new IF_CHAR(2, "fuel_type"),
            /*019*/ new IF_CHAR(1, "trans_type"),
            /*020*/ new IF_CHAR(2, "nozzle_id"),
            /*021*/ new IFA_LLCHAR(99, "userCard_id"),
            /*022*/ new IFA_LLCHAR(99, "fuel_sam_id"),
            /*023*/ new IFA_LLCHAR(99, "total_amount"),
            /*024*/ new IFA_LLCHAR(99, "N"),
            /*025*/ new IF_CHAR(1, "fuel_status"),
            /*026*/new IFA_LLCHAR(99, "X"),
            /*027*/new IFA_LLCHAR(99, "X1"),
            /*028*/new IFA_LLCHAR(99, "X2"),
            /*029*/new IFA_LLCHAR(99, "X3"),
            /*030*/new IFA_LLCHAR(99, "R"),
            /*031*/new IFA_LLCHAR(99, "R1"),
            /*032*/new IFA_LLCHAR(99, "R2"),
            /*033*/new IFA_LLCHAR(99, "R3"),
            /*034*/new IFA_LLCHAR(99, "FTC"),
            /*035*/new IFA_LLCHAR(99, "payment_sam_id"),
            /*036*/new IFA_LLCHAR(99, "total_cost"),
            /*037*/new IFA_LLCHAR(99, "C"),
            /*038*/new IFA_LLCHAR(99, "C1"),
            /*039*/new IFA_LLCHAR(99, "C2"),
            /*040*/new IFA_LLCHAR(99, "C3"),
            /*041*/new IFA_LLCHAR(99, "P"),
            /*042*/new IFA_LLCHAR(99, "P1"),
            /*043*/new IFA_LLCHAR(99, "P2"),
            /*044*/new IFA_LLCHAR(99, "P3"),
            /*045*/new IFA_LLCHAR(99, "cash_payment"),
            /*046*/new IFA_LLCHAR(99, "card_payment"),
            /*047*/new IFA_LLCHAR(99, "ctc"),
            /*048*/new IFA_LLCHAR(99, "TAC"),
            /*049*/new IFA_LLCHAR(99, "before_balance"),
            /*050*/new IFA_LLCHAR(99, "after_balance"),
            /*051*/new IFA_LLCHAR(99, "RFU"),
            /*052*/new IF_CHAR(1, "upload_flag"),
            /*053*/ new IFA_NUMERIC ( 16, "SECURITY RELATED CONTROL INFORMATION"),
            /*054*/ new IFA_LLLCHAR (120, "ADDITIONAL AMOUNTS"),
            /*055*/ new IFA_LLLCHAR (999, "RESERVED ISO"),
            /*056*/ new IFA_LLLCHAR (999, "RESERVED ISO"),
            /*057*/ new IFA_LLLCHAR (999, "RESERVED NATIONAL"),
            /*058*/ new IFA_LLLCHAR (999, "RESERVED NATIONAL"),
            /*059*/ new IFA_LLLCHAR (999, "RESERVED NATIONAL"),
            /*060*/ new IFA_LLLCHAR (999, "RESERVED PRIVATE"),
            /*061*/ new IFA_LLLCHAR (999, "RESERVED PRIVATE"),
            /*062*/ new IFA_LLLCHAR (999, "RESERVED PRIVATE"),
            /*063*/ new IFA_LLLCHAR (999, "RESERVED PRIVATE"),
            /*064*/ new IFA_BINARY  (  16, "MESSAGE AUTHENTICATION CODE FIELD")
    };

    public GsPackager() {
        super();
        setFieldPackager(fld);
    }
}
