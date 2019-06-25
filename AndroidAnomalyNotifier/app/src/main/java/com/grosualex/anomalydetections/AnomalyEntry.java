package com.grosualex.anomalydetections;

import android.content.Context;
import android.support.v7.app.AppCompatActivity;
import android.util.Pair;
import android.view.LayoutInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.ListAdapter;
import android.widget.ListView;
import android.widget.TextView;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;


public class AnomalyEntry extends BaseAdapter implements ListAdapter {
    private ArrayList<Pair<Integer, AnomalyData>> list = new ArrayList<>();
    private MainActivity context;

    private static final String DECISION_CONTINUE = "continue";
    private static final String DECISION_STOP     = "stop";
    private static final String DECISION_CRITICAL = "critical";
    private String serverIP;

    public AnomalyEntry(MainActivity context, String serverIP) {
        this.context = context;
        this.serverIP = serverIP;
        this.list = new ArrayList<>();

        refresh();
    }

    @Override
    public int getCount() {
        return list.size();
    }

    @Override
    public Object getItem(int pos) {
        return list.get(pos);
    }

    @Override
    public long getItemId(int pos) {
        /*return list.get(pos).getId();
        */
        //just return 0 if your list items do not have an Id variable.
        return 0;
    }

    @Override
    public View getView(final int position, View convertView, ViewGroup parent) {
        View view = convertView;
        if (view == null) {
            LayoutInflater inflater = (LayoutInflater) context.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
            view = inflater.inflate(R.layout.list_entry, null);
        }

        //Handle TextView and display string from your list
        TextView listItemText = (TextView)view.findViewById(R.id.list_item_string);
        Pair<Integer, AnomalyData> pereche = list.get(position);
        listItemText.setText(pereche.second.getTitle());

        //Handle buttons and add onClickListeners
//        Button stopProcessBtn = (Button)view.findViewById(R.id.stop_proc_btn);
//        Button continueProcessBtn = (Button)view.findViewById(R.id.cont_proc_btn);
//        Button criticalAnomalyBtn = (Button)view.findViewById(R.id.critical_btn);

//        stopProcessBtn.setOnClickListener(new View.OnClickListener(){
//            @Override
//            public void onClick(View v) {
//                sendDecisionToServer(DECISION_STOP, list.get(position).first);
//                list.remove(position);
//
//                fetchEntries();
//            }
//        });
//        continueProcessBtn.setOnClickListener(new View.OnClickListener(){
//            @Override
//            public void onClick(View v) {
//                sendDecisionToServer(DECISION_CONTINUE, list.get(position).first);
//                list.remove(position);
//
//                fetchEntries();
//            }
//        });
//
//        criticalAnomalyBtn.setOnClickListener(new View.OnClickListener(){
//            @Override
//            public void onClick(View v) {
//                sendDecisionToServer(DECISION_CRITICAL, list.get(position).first);
//                list.remove(position);
//
//                fetchEntries();
//            }
//        });

        return view;
    }

    public int getNeededEntries() {
        return 50 - list.size();
    }

    public void addToList(Pair<Integer, AnomalyData> pair) {
        list.add(pair);
    }

    private void fetchEntries() {
        HashMap<String, Object> params = new HashMap<>();
        params.put("needed_entries", getNeededEntries());
        params.put("server_ip", getServerIP());

        ArrayList excludeIDS = new ArrayList();

        for (Pair<Integer, AnomalyData> pair: list) {
            excludeIDS.add(pair.first);
        }

        params.put("to_exclude", excludeIDS);

        new TopUnsolvedAnomaliesFetcher(new TopUnsolvedAnomaliesFetcher.AsyncResponse(){

            @Override
            public void processFinish(HashMap output) {

                ArrayList<Pair<Integer, AnomalyData>> anomalies_resulted = (ArrayList<Pair<Integer, AnomalyData>>) output.get("anomalies");

                if (anomalies_resulted != null) {
                    list.addAll(anomalies_resulted);
                    notifyDataSetChanged();

                    MenuItem item = context.findViewById(R.id.learning);

                    if ((boolean) output.get("learning")) {
                        context.learning = true;
                        context.learningText = "switch to Detecting Mode";
                    } else {
                        context.learning = false;
                        context.learningText = "switch to Learning Mode";
                    }
                }
                else {
                    System.out.println("Server did not respond when fetching anomalies.");
                }



            }

        }).execute(params);
    }

    public String getServerIP() {
        return serverIP;
    }

    public void setServerIP(String serverIP) {
        this.serverIP = serverIP;
    }

    public void refresh() {
        fetchEntries();
    }

    public void remove(int pos) {
        list.remove(pos);
        fetchEntries();
    }
}
