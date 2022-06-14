package com.shopme.admin.utils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Log {
    private static final Logger log = LogManager.getLogger(Log.class);

    public static void info(String msg) {
        log.info(msg);
    }

    public static void warn(String msg) {
        log.warn(msg);
    }

    public static void error(String msg) {
        log.error(msg);
    }

    public static void fatal(String msg) {
        log.fatal(msg);
    }

    public static void debug(String msg) {
        log.debug(msg);
    }

    public static void trace(String msg) {
        log.trace(msg);
    }
}
