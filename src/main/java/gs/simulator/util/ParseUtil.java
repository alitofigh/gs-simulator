package gs.simulator.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static java.lang.Character.isSpaceChar;

/**
 * Created by A_Tofigh at 08/02/2024
 */
public class ParseUtil {

    public static List<String> splitTokens(String statement) {
        //return commandLine.trim().split(" ");
        List<String> commandAndArgs = new ArrayList<>();
        StringBuilder parseBuffer = new StringBuilder(statement);
        int startIndex = -1;
        int endIndex = -1;
        boolean insideQuote = false;
        char currentQuoteChar = '\"';
        for (int i = 0; i < parseBuffer.length(); i++) {
            if (!insideQuote && isSpaceChar(parseBuffer.charAt(i))) {
                if (i != 0 && !isSpaceChar(parseBuffer.charAt(i - 1))) {
                    endIndex = i;
                    if (parseBuffer.charAt(i - 1) == '\''
                            || parseBuffer.charAt(i - 1) == '\"')
                        endIndex--;
                    commandAndArgs.add(
                            parseBuffer.substring(startIndex, endIndex));
                }
            } else {
                if (!insideQuote
                        && (i == 0 || isSpaceChar(parseBuffer.charAt(i - 1))))
                    startIndex = i;
                if (parseBuffer.charAt(i) == '\''
                        || parseBuffer.charAt(i) == '\"') {
                    if (insideQuote) {
                        if (parseBuffer.charAt(i) == currentQuoteChar) {
                            endIndex = i;
                            insideQuote = false;
                        }
                    } else {
                        insideQuote = true;
                        currentQuoteChar = parseBuffer.charAt(i);
                        startIndex++;
                    }
                }
                if (i == parseBuffer.length() - 1) {
                    if (endIndex < startIndex)
                        endIndex = parseBuffer.length();
                    commandAndArgs.add(
                            parseBuffer.substring(startIndex, endIndex));
                }
            }
        }
        return commandAndArgs;
    }
}
