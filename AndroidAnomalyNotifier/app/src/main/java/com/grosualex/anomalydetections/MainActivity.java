package com.grosualex.anomalydetections;

import android.app.Application;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.support.v4.app.NotificationCompat;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.support.v7.preference.PreferenceManager;
import android.util.Pair;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.Button;
import android.widget.ListView;

import java.io.IOException;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;

public class MainActivity extends AppCompatActivity implements SharedPreferences.OnSharedPreferenceChangeListener {

    private static final String CHANNEL_ID = "anomaly_detection_channel";

    private Menu optionsMenu;
    AnomalyEntry adapter = null;
    Intent backgroundSensor;
    ListView lView;
    Context context = this;
    String learningText;
    boolean learning;
    static Thread refresh = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        SharedPreferences sharedPreferences = PreferenceManager.getDefaultSharedPreferences(this);
        sharedPreferences.registerOnSharedPreferenceChangeListener(this);

        backgroundSensor = new Intent(this, BackgroundSensor.class);
        String server_ip = sharedPreferences.getString(
                getString(R.string.server_ip_key),
                getString(R.string.server_ip_default));
        backgroundSensor.putExtra("server_ip", server_ip);
        startService(backgroundSensor);

        adapter = new AnomalyEntry( this, server_ip);

        lView = (ListView) findViewById(R.id.anomalies);
        lView.setAdapter(adapter);

        lView.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int pos, long id) {
                Intent intent = new Intent(view.getContext(), AnomalyActivity.class);
                Pair<Integer, AnomalyData> pair = (Pair<Integer, AnomalyData>) adapter.getItem(pos);
                intent.putExtra("text", pair.second.getText());
                intent.putExtra("anomalyID", pair.first);
                intent.putExtra("stoppedPIDs", pair.second.getStoppedPIDs());
                intent.putExtra("listPosition", pos);
                intent.putExtra("serverIP", adapter.getServerIP());
                startActivity(intent);
            }
        });

        if (refresh != null) {
            refresh.interrupt();
        }

        refresh = new Thread(new Runnable() {
            @Override
            public void run() {
                while (true) {
                    try {
                        Thread.sleep(5000);
                        adapter.refresh();
                    }
                    catch(InterruptedException e){
                        Thread.currentThread().interrupt();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
        });
        refresh.start();

    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        this.optionsMenu = menu;
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.menu_main, menu);
        return super.onCreateOptionsMenu(menu);
    }
    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case R.id.entries_refresh:
                adapter.refresh();
                return true;
            case R.id.learning:
                HashMap<String, Object> params = new HashMap<>();
                params.put("serverIP", adapter.getServerIP());
                new ChangeLearningMode().execute(params);

                return true;
            case R.id.action_settings:
                Intent intent = new Intent(MainActivity.this, SettingsActivity.class);
                startActivity(intent);
                return true;
        }
        return super.onOptionsItemSelected(item);
    }

    @Override
    public boolean onPrepareOptionsMenu(Menu menu) {
        MenuItem item = menu.findItem(R.id.learning);
        if (learningText == null) {
            item.setTitle("Please Refresh");
        }
        else {
            item.setTitle(learningText);
        }

        return super.onPrepareOptionsMenu(menu);
    }

    @Override
    public void onSharedPreferenceChanged(SharedPreferences sharedPreferences, String key) {
        System.out.println("CHANGED SHARED" + key);
        if (key.equals(getString(R.string.server_ip_key))) {
            stopService(backgroundSensor);
            String new_server_ip;

            new_server_ip = sharedPreferences.getString(
                    getString(R.string.server_ip_key),
                    getString(R.string.server_ip_default));

            System.out.println("NEW SERVER IP " + new_server_ip);

            backgroundSensor.putExtra("server_ip", new_server_ip);
            startService(backgroundSensor);

            adapter.setServerIP(new_server_ip);

            lView.setOnItemClickListener(new AdapterView.OnItemClickListener() {
                @Override
                public void onItemClick(AdapterView<?> parent, View view, int pos, long id) {
                    Intent intent = new Intent(view.getContext(), AnomalyActivity.class);
                    Pair<Integer, AnomalyData> pair = (Pair<Integer, AnomalyData>) adapter.getItem(pos);
                    intent.putExtra("text", pair.second.getText());
                    intent.putExtra("anomalyID", pair.first);
                    intent.putExtra("stoppedPIDs", pair.second.getStoppedPIDs());
                    intent.putExtra("listPosition", pos);
                    intent.putExtra("serverIP", adapter.getServerIP());
                    startActivityForResult(intent, 0);
                }
            });
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        System.out.println(resultCode);
        System.out.println("RESULT");
        if (resultCode == RESULT_OK) {
            int pos = data.getIntExtra("pos", -1);
            adapter.remove(pos);
        }
    }

    @Override
    protected void onDestroy() {
        // TODO Auto-generated method stub
        refresh.interrupt();
        super.onDestroy();
    }
}
