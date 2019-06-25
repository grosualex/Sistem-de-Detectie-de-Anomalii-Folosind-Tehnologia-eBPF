package com.grosualex.anomalydetections;

import android.os.AsyncTask;
import android.util.Pair;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;

public class DecisionSender extends AsyncTask<HashMap<String, Object>, Void, Boolean> {

    public interface AsyncResponse {
        void processFinish(boolean output);
    }

    public AsyncResponse delegate = null;

    public DecisionSender(AsyncResponse delegate){
        this.delegate = delegate;
    }

    @Override
    protected void onPostExecute(Boolean done) {
        delegate.processFinish(done);
    }

    @Override
    protected Boolean doInBackground(HashMap<String, Object>... params) {
        HashMap arguments = params[0];
        String    decision = (String) arguments.get("decision");
        int       anomaly_id = (int) arguments.get("anomaly_id");
        String    serverIp = (String) arguments.get("server_ip");
        ArrayList killPIDs = (ArrayList) arguments.get("killPIDs");
        boolean   isAnomaly = (boolean) arguments.get("isAnomaly");
        JSONArray jsonKillPIDs = new JSONArray(killPIDs);

        try {
            JSONObject object = new JSONObject();
            try {
                object.put("decision", decision);
                object.put("anomaly_id", anomaly_id);
                object.put("kill_pids", jsonKillPIDs);
                object.put("is_anomaly", isAnomaly);
            } catch (JSONException e) {
                e.printStackTrace();
            }

            byte[] jsonBytes = object.toString().getBytes("UTF-8");

            System.out.println(serverIp);
            URL url = new URL("http://" + serverIp + ":6578/decision");

            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("PUT");
            connection.setConnectTimeout(10000);
            connection.setReadTimeout(10000);
            connection.setDoInput(false);
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("Content-Length", Integer.toString(jsonBytes.length));

            OutputStream osBody = connection.getOutputStream();

            osBody.write(jsonBytes);
            osBody.close();

            connection.connect();

            if (connection.getResponseCode() != HttpURLConnection.HTTP_OK) {
                return false;
            }

        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return false;
        } catch (ProtocolException e) {
            e.printStackTrace();
            return false;
        } catch (MalformedURLException e) {
            e.printStackTrace();
            return false;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }

        return true;
    }
}
