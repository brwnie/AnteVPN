package uk.co.crazyfools.antevpn;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.IOException;
import java.net.InetAddress;

public class ExternalComms {

    private static String runAPICall(String apiAddress) throws IOException {
        OkHttpClient client = new OkHttpClient().newBuilder().build();
        Request request = new Request.Builder().url(apiAddress).method("GET", null).build();
        Response response = client.newCall(request).execute();
        String responseBody = response.body().string();
        response.close();
        return responseBody;
    }

    private static JSONObject parseJson(String jsonText) {
        JSONObject jsonObject = new JSONObject();
        JSONParser jsonParser = new JSONParser();

        try {
            jsonObject = (JSONObject) jsonParser.parse(jsonText);
        } catch (ParseException e) {
            // Could not translate JSON object
            Main.logMessage("Failed to translate JSON Object");
        }

        return jsonObject;
    }

    public static Integer ipTrooper(InetAddress address) {
        String apiAddress = "https://api.iptrooper.net/check/" + address + "?full=1";
        String apiCallResult = "";
        try {
            apiCallResult = runAPICall(apiAddress);
        } catch (IOException e) {
            e.printStackTrace();
            return 2;
        }

        JSONObject jsonObject = new JSONObject();

        jsonObject = parseJson(apiCallResult);

        if(jsonObject.containsKey("bad")) {
            if(jsonObject.get("bad").toString().equalsIgnoreCase("true")) {
                if(jsonObject.get("type").toString().equalsIgnoreCase("proxy")) {
                        Main.debugMessage("IPTrooper: VPN Detected on " + address.getHostAddress() + "!");
                    return 1;
                }
            }
        } else {
            return 2;
        }

        return 0;
    }

    public static Integer ipQualityScore(InetAddress address) {
        if(Main.providerKeys.containsKey("IPQUALITYSCORE")) {
            String apiAddress = "https://ipqualityscore.com/api/json/ip/" + Main.providerKeys.get("IPQUALITYSCORE") + "/" + address.getHostAddress() + "?strictness=0&allow_public_access_points=true&fast=true&lighter_penalties=true&mobile=false";
            String apiCallResult = "";
            try {
                apiCallResult = runAPICall(apiAddress);
            } catch (IOException e) {
                e.printStackTrace();
                return 2;
            }

            JSONObject jsonObject = new JSONObject();

            jsonObject = parseJson(apiCallResult);

            if (jsonObject.containsKey("proxy")) {
                if (jsonObject.get("proxy").toString().equalsIgnoreCase("true")) {
                        Main.debugMessage("IPQualityScore.com: VPN Detected on " + address.getHostAddress() + "!");
                    return 1;
                }
            } else {
                return 2;
            }

            return 0;
        } else {
            return 2;
        }
    }

    public static Integer proxyCheckIo(InetAddress address)  {
        String apiAddress = "";

        if(Main.providerKeys.containsKey("PROXYCHECK-IO")) {
            apiAddress = "https://proxycheck.io/v2/" + address.getHostAddress() + "?key=" + Main.providerKeys.get("PROXYCHECK-IO") + "&vpn=1";
        } else {
            apiAddress = "https://proxycheck.io/v2/" + address.getHostAddress() + "?vpn=1";
        }

        String apiCallResult = "";
        try {
            apiCallResult = runAPICall(apiAddress);
        } catch (IOException e) {
            e.printStackTrace();
            return 2;
        }

        // Parse Response
        JSONObject jsonResponse = new JSONObject();

        jsonResponse = parseJson(apiCallResult);

        // Now checking for VPN

        if(jsonResponse.containsKey(address.getHostAddress())) {
                Main.debugMessage("Address value found");
            JSONObject jsonAddress = (JSONObject) jsonResponse.get(address.getHostAddress());
            if(jsonAddress.containsKey("proxy")) {
                if(jsonAddress.get("proxy").toString().equalsIgnoreCase("yes")) {
                        Main.debugMessage("ProxyCheck: VPN Detected on " + address.getHostAddress() + "!");
                    return 1;
                }
            }
        } else {
            return 2;
        }


        return 0;

    }
}
