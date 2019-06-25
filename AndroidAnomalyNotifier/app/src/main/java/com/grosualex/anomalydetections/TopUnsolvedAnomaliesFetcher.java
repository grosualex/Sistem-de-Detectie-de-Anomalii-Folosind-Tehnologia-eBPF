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
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;

public class TopUnsolvedAnomaliesFetcher extends AsyncTask<HashMap<String, Object>, Void, HashMap<String, Object>>{

    public interface AsyncResponse {
        void processFinish(HashMap output);
    }

    public AsyncResponse delegate = null;

    public TopUnsolvedAnomaliesFetcher(AsyncResponse delegate){
        this.delegate = delegate;
    }

    @Override
    protected void onPostExecute(HashMap result) {
        delegate.processFinish(result);
    }

    @Override
    protected HashMap doInBackground(HashMap<String, Object>... params) {
        HashMap toReturn = new HashMap();
        ArrayList<Pair<Integer, AnomalyData>> toReturnAnomalies = new ArrayList<Pair<Integer, AnomalyData>>();

        HashMap<String, Object> arguments = params[0];

        int current_number = (int) arguments.get("needed_entries");
        ArrayList ids = (ArrayList) arguments.get("to_exclude");
        String serverIP = (String) arguments.get("server_ip");

        try {
            JSONObject object = new JSONObject();
            JSONArray excludedIDS = new JSONArray(ids);
            try {
                object.put("entries_number", current_number);
                object.put("to_exclude", excludedIDS);
            } catch (JSONException e) {
                e.printStackTrace();
            }

            byte[] jsonBytes = object.toString().getBytes("UTF-8");

            URL url = new URL("http://" + serverIP + ":6578/entries");

            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setConnectTimeout(10000);
            connection.setReadTimeout(10000);
            connection.setDoInput(true);
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("Content-Length", Integer.toString(jsonBytes.length));

            OutputStream osBody = connection.getOutputStream();

            osBody.write(jsonBytes);
            osBody.close();

            connection.connect();

            if (connection.getResponseCode() != HttpURLConnection.HTTP_OK) {
                return null;
            }

            StringBuilder result = new StringBuilder();
            InputStreamReader input = new InputStreamReader(connection.getInputStream());
            BufferedReader reader = new BufferedReader(input);

            String line;
            while ((line = reader.readLine()) != null) {
                result.append(line);
            }

            JSONArray  objects;
            JSONObject response;
            boolean    learning;
            try {
                response = new JSONObject(result.toString());
                learning = response.getBoolean("learning");
                objects = response.getJSONArray("anomalies");

                for (int i = 0; i < objects.length(); i++) {
                    JSONObject entry = objects.getJSONObject(i);
                    JSONArray  stoppedPIDs = entry.getJSONArray("stopped_pids");

                    ArrayList<String> auxList= new ArrayList<>();

                    for (int j = 0; j < stoppedPIDs.length(); j++) {
                        auxList.add(stoppedPIDs.getString(j));
                    }

                    toReturnAnomalies.add(new Pair<Integer, AnomalyData>(
                            entry.getInt("anomaly_id"),
                            new AnomalyData(
                                    entry.getString("anomaly_title"),
                                    entry.getString("anomaly_text"),
                                    auxList)));
                }

                toReturn.put("learning", learning);
                toReturn.put("anomalies", toReturnAnomalies);
            } catch (JSONException e) {
                e.printStackTrace();
            }

            reader.close();
            input.close();

        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return toReturn;
    }
}
