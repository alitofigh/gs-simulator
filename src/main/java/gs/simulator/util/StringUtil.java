package gs.simulator.util;

/**
 * Created by A_Tofigh at 08/02/2024
 */
public class StringUtil {

    public static String fixWidthZeroPad(String text, int desiredLen) {
        return fixWidth(text, desiredLen, '0', true);
    }

    public static String fixWidthSpacePad(String text, int desiredLen) {
        return fixWidth(text, desiredLen, ' ', false);
    }

    public static String fixWidth(
            String text, int desiredLen, char paddingChar, boolean leftPad) {
        return fixWidth(text, desiredLen, "" + paddingChar, leftPad);
    }

    public static String fixWidth(
            String text, int desiredLen, String padder, boolean leftPad) {
        if (text == null)
            text = "";
        if (text.length() >= desiredLen) {
            // Consider important part of data when stripping away some of chars
            return leftPad
                    ? text.substring(text.length() - desiredLen, text.length())
                    : text.substring(0, desiredLen);
        }
        StringBuilder stringBuilder = new StringBuilder(desiredLen);
        int fillLen = desiredLen - text.length();
        if (!leftPad)
            stringBuilder.append(text);
        while (fillLen-- > 0)
            stringBuilder.append(padder);
        if (leftPad)
            stringBuilder.append(text);
        return stringBuilder.toString();
    }
}
