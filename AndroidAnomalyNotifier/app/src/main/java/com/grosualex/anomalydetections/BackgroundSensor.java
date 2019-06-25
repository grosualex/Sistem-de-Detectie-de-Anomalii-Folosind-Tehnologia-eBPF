package com.grosualex.anomalydetections;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.media.AudioAttributes;
import android.media.AudioManager;
import android.media.Ringtone;
import android.media.RingtoneManager;
import android.net.Uri;
import android.os.Build;
import android.os.IBinder;
import android.support.v4.app.NotificationCompat;
import android.support.v4.app.NotificationManagerCompat;
import android.support.v4.graphics.drawable.IconCompat;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Random;

import dalvik.system.BaseDexClassLoader;

public class BackgroundSensor extends Service {

    private boolean isRunning = false;
    private Socket socket;
    private Thread backgroundThread;
    private NotificationManager notificationManager;

    private static final int SERVERPORT = 6579;
    private String SERVER_IP;
    private String CHANNEL_ID = "anomaly_detection_channel";

    Context context;

    public BackgroundSensor() {
        this.context = this;
    }

    public BackgroundSensor(Context context) {
        super();
        this.context = context;
    }

    @Override
    public void onCreate() {
        isRunning = false;
        backgroundThread = new Thread(startListening);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startID) {
        super.onStartCommand(intent, flags, startID);

        SERVER_IP = intent.getStringExtra("server_ip");

        if (!isRunning) {
            backgroundThread.start();
        }

        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        this.isRunning = false;
        try {
            if (socket != null) {
                socket.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        backgroundThread.interrupt();
        while (!backgroundThread.isInterrupted()) {
            backgroundThread.interrupt();
        }
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            CharSequence name = getString(R.string.channel_name);
            String description = getString(R.string.channel_description);
            int importance = NotificationManager.IMPORTANCE_DEFAULT;
            NotificationChannel channel = new NotificationChannel(CHANNEL_ID, name, importance);
            channel.setDescription(description);

            Uri alarmSound = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION);

            AudioAttributes audioAttributes = new AudioAttributes.Builder()
                    .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                    .setUsage(AudioAttributes.USAGE_NOTIFICATION_RINGTONE)
                    .build();

            channel.enableLights(true);
            channel.enableVibration(true);
            channel.canBypassDnd();
            channel.setSound(alarmSound, audioAttributes);

            notificationManager = getSystemService(NotificationManager.class);
            notificationManager.createNotificationChannel(channel);
        }
    }

    private Runnable startListening = new Runnable() {
        @Override
        public void run() {
            isRunning = true;
            createNotificationChannel();

            while (true) {
                System.out.println("Connecting to server " + SERVER_IP);
                BufferedReader in = null;
                BufferedWriter out = null;

                try {
                    InetAddress serverAddr = InetAddress.getByName(SERVER_IP);
                    socket = new Socket(serverAddr, SERVERPORT);

                    in = new BufferedReader(new InputStreamReader(socket.getInputStream()), 8 * 1024);
                    out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()), 8 * 1024);
                } catch (IOException e) {
                    e.printStackTrace();
                    try {
                        Thread.sleep(5000);
                    } catch (InterruptedException e1) {
                        e1.printStackTrace();
                    }

                    continue;
                }

                while (true) {
                    try {
                        String result = in.readLine();
                        System.out.print(" reading result ->");
                        System.out.println(result);

                        if (result != null && result.contains("alert") && Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                            Intent notificationIntent = new Intent(context, MainActivity.class);
                            notificationIntent.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP
                                    | Intent.FLAG_ACTIVITY_SINGLE_TOP);

                            PendingIntent intent = PendingIntent.getActivity(context, 0,
                                    notificationIntent, 0);

                            Notification newMessageNotification = new Notification.Builder(context, CHANNEL_ID)
                                    .setSmallIcon(R.drawable.ic_launcher_background)
                                    .setContentTitle("Anomaly Detected")
                                    .setContentText("Please check anomaly provenience")
                                    .setContentIntent(intent)
                                    .build();

                            Random random = new Random();

                            AudioManager audio = (AudioManager) getSystemService(context.AUDIO_SERVICE);
                            int currentVolume = audio.getStreamVolume(AudioManager.STREAM_NOTIFICATION);
                            int maxVolume = audio.getStreamMaxVolume(AudioManager.STREAM_NOTIFICATION);

                            audio.setStreamVolume(AudioManager.STREAM_NOTIFICATION, maxVolume, 0);
                            notificationManager.notify(random.nextInt(), newMessageNotification);
                            audio.setStreamVolume(AudioManager.STREAM_NOTIFICATION, currentVolume, 0);
                        }

                        out.write("ms\n");
                        out.flush();

                        Thread.sleep(2000);

                        System.out.println("MSSS");

                    } catch (IOException e) {
                        e.printStackTrace();
                        try {
                            in.close();
                            out.close();
                        } catch (IOException e1) {
                            e1.printStackTrace();
                        }

                        break;
                    } catch (InterruptedException e) {
                        e.printStackTrace();

                        isRunning = false;

                        try {
                            in.close();
                            out.close();

                            if (socket != null) {
                                socket.close();
                            }
                        } catch (IOException e1) {
                            e1.printStackTrace();
                        }
                        return;
                    }
                }

                try {

                    if (socket != null) {
                        socket.close();
                    }

                    if (in != null) {
                        in.close();
                    }

                    if (out != null) {
                        out.close();
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }

            }
        }
    };

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
