package com.bsep.pki.util;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DnParserUtil {

    public static String extractField(String dn, String key) {
        if (dn == null || key == null) {
            return "N/A";
        }
        Pattern pattern = Pattern.compile(key + "=([^,]+)");
        Matcher matcher = pattern.matcher(dn);
        if (matcher.find()) {
            return matcher.group(1).trim();
        }
        return "N/A";
    }
}