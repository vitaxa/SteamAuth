package com.vitaxa.steamauth.helper;

import static java.lang.System.currentTimeMillis;

public final class CommonHelper {

    private CommonHelper() {
    }

    public static Thread newThread(String name, boolean daemon, Runnable runnable) {
        Thread thread = new Thread(runnable);
        thread.setDaemon(daemon);
        if (name != null) {
            thread.setName(name);
        }
        return thread;
    }

    public static long getUnixTimeStamp() {
        return currentTimeMillis() / 1000L;
    }
}
