package com.vitaxa.steamauth;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import com.google.gson.reflect.TypeToken;
import com.vitaxa.steamauth.helper.CommonHelper;
import com.vitaxa.steamauth.http.HttpMethod;
import com.vitaxa.steamauth.http.HttpParameters;
import com.vitaxa.steamauth.model.SteamResponse;

import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.*;

public final class TimeAligner {
    private static final ThreadFactory THREAD_FACTORY = r -> CommonHelper.newThread("TimeAligner Thread", true, r);
    private static final ExecutorService THREAD_POOL = Executors.newSingleThreadExecutor(THREAD_FACTORY);

    private static boolean aligned = false;
    private static int timeDifference = 0;

    private TimeAligner() {
    }

    public static long getSteamTime() {
        if (!aligned) {
            alignTime();
        }
        return CommonHelper.getUnixTimeStamp() + timeDifference;
    }

    public static long getSteamTimeAsync() {
        if (!aligned) {
            THREAD_POOL.submit(TimeAligner::alignTime);
        }
        return CommonHelper.getUnixTimeStamp() + timeDifference;
    }

    public static void alignTime() {
        long currentTime = CommonHelper.getUnixTimeStamp();

        Map<String, String> params = new HashMap<>();
        params.put("steamid", "0");
        String response = SteamWeb.fetch(APIEndpoints.TWO_FACTOR_TIME_QUERY, new HttpParameters(params, HttpMethod.POST));

        System.out.println("RESPONSE ALIGNTIME " +  response);

        Type responseType = new TypeToken<SteamResponse<TimeQuery>>(){}.getType();
        SteamResponse steamResponse = new Gson().fromJson(response, responseType);

        TimeQuery query = (TimeQuery) steamResponse.getResponse();

        timeDifference = (int) (query.serverTime - currentTime);
        aligned = true;
    }

    private final class TimeQuery {
        @SerializedName("server_time")
        public long serverTime;
    }

}
