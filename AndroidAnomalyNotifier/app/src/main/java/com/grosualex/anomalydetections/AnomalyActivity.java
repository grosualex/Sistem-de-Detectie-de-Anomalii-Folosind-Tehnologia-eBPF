package com.grosualex.anomalydetections;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.support.v4.app.NavUtils;
import android.support.v7.app.ActionBar;
import android.support.v7.app.AppCompatActivity;
import android.util.Pair;
import android.util.StateSet;
import android.view.LayoutInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.ListAdapter;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.HashMap;

public class AnomalyActivity extends AppCompatActivity {
    String    text;
    Integer   anomalyID;
    ArrayList stoppedPIDs;
    ArrayList toKillPIDs = new ArrayList();

    String      serverIP;
    Integer     anomaliesListPos = -1;
    PIDsAdapter adapter;
    Context     context;
    ArrayList   toKillPositions;
    boolean     isAnomaly = true;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_anomaly_decision);

        context = this;

        ActionBar actionBar = this.getSupportActionBar();

        if (actionBar != null) {
            actionBar.setDisplayHomeAsUpEnabled(true);
        }

        Intent intent = getIntent();

        text             = intent.getStringExtra("text");
        anomalyID        = intent.getIntExtra("anomalyID", -1);
        stoppedPIDs      = intent.getStringArrayListExtra("stoppedPIDs");
        anomaliesListPos = intent.getIntExtra("listPosition", -1);
        serverIP         = intent.getStringExtra("serverIP");
        toKillPositions  = new ArrayList();


        ArrayList toDelete = new ArrayList();

        for (Object pid : stoppedPIDs) {
            String auxText = (String) pid;
            if (auxText.length() < 2) {
                toDelete.add(pid);
            }
        }

        for (Object pid: toDelete) {
            stoppedPIDs.remove(pid);
        }

        TextView textView = (TextView) findViewById(R.id.anomaly_text);
        textView.setText(text);

        ListView lView = (ListView) findViewById(R.id.stopped_pids_list);
        adapter = new PIDsAdapter(this);
        lView.setAdapter(adapter);
        setListViewHeightBasedOnChildren(lView);

        final Button criticalBtn = findViewById(R.id.critical_btn);
        final Button doneBtn = (Button) findViewById(R.id.done_btn);
        final Button noAnomaly = (Button) findViewById(R.id.no_anomaly);

        noAnomaly.setOnClickListener(new View.OnClickListener(){
            @Override
            public void onClick(View v) {
                isAnomaly = false;
                noAnomaly.setVisibility(View.GONE);
            }
        });

        criticalBtn.setOnClickListener(new View.OnClickListener(){
            @Override
            public void onClick(View v) {
                sendDecision("critical");
                ViewGroup layout = (ViewGroup) criticalBtn.getParent();
                layout.removeView(criticalBtn);
                layout.removeView(doneBtn);
            }
        });

        doneBtn.setOnClickListener(new View.OnClickListener(){
            @Override
            public void onClick(View v) {
                sendDecision("done");
                ViewGroup layout = (ViewGroup) criticalBtn.getParent();
                layout.removeView(criticalBtn);
                layout.removeView(doneBtn);
            }
        });
    }

    public void sendDecision(String decision) {
        HashMap params = new HashMap();
        params.put("decision", decision);
        params.put("anomaly_id", anomalyID);
        params.put("server_ip", serverIP);
        params.put("killPIDs", toKillPIDs);
        params.put("isAnomaly", isAnomaly);
        new DecisionSender(new DecisionSender.AsyncResponse() {

            @Override
            public void processFinish(boolean done) {
                if (done) {
                    System.out.println("FINISHING WITH RESULT OK");
                    Intent resultIntent = new Intent();
                    resultIntent.putExtra("pos", anomaliesListPos);
                }
                else {
                    Toast.makeText(getApplicationContext(),
                            "Cannot send response to server.",
                            Toast.LENGTH_SHORT).show();

                    setResult(RESULT_CANCELED, null);
                }
            }

        }).execute(params);
    }

    public static void setListViewHeightBasedOnChildren(ListView listView) {
        ListAdapter listAdapter = listView.getAdapter();
        if (listAdapter == null)
            return;

        int desiredWidth = View.MeasureSpec.makeMeasureSpec(listView.getWidth(), View.MeasureSpec.UNSPECIFIED);
        int totalHeight = 0;
        View view = null;
        for (int i = 0; i < listAdapter.getCount(); i++) {
            view = listAdapter.getView(i, view, listView);
            if (i == 0)
                view.setLayoutParams(new ViewGroup.LayoutParams(desiredWidth, ViewGroup.LayoutParams.WRAP_CONTENT));

            view.measure(desiredWidth, View.MeasureSpec.UNSPECIFIED);
            totalHeight += view.getMeasuredHeight();
        }
        ViewGroup.LayoutParams params = listView.getLayoutParams();
        params.height = totalHeight + (listView.getDividerHeight() * (listAdapter.getCount() - 1));
        listView.setLayoutParams(params);
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();
        if (id == android.R.id.home) {
            NavUtils.navigateUpFromSameTask(this);
        }
        return super.onOptionsItemSelected(item);
    }

    class PIDsAdapter extends BaseAdapter implements ListAdapter {

        Context context;
        public PIDsAdapter(Context context) {
            this.context = context;
        }

        @Override
        public int getCount() {
            System.out.println("SIZE");
            System.out.println(stoppedPIDs.size());
            return stoppedPIDs.size();
        }

        @Override
        public Object getItem(int position) {
            return stoppedPIDs.get(position);
        }

        @Override
        public long getItemId(int position) {
            return 0;
        }

        @Override
        public View getView(final int position, View convertView, ViewGroup parent) {
            View view = convertView;
            if (view == null) {
                LayoutInflater inflater = (LayoutInflater) context.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
                view = inflater.inflate(R.layout.list_pids_decision, null);
            }

            String text = (String) stoppedPIDs.get(position);

            System.out.println("Position");
            System.out.println(position);

            TextView  textView = (TextView) view.findViewById(R.id.pid_text);
            textView.setText(text);

            final Button killBtn = (Button)view.findViewById(R.id.kill_pid_btn);

            if (killBtn != null) {
                killBtn.setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View v) {
                        toKillPIDs.add(stoppedPIDs.get(position));
                        // stoppedPIDs.remove(position);

                        ViewGroup parentView = (ViewGroup) v.getParent();
                        parentView.removeView(killBtn);

                        notifyDataSetChanged();
                    }
                });
            }

            return view;

        }
    }

}
