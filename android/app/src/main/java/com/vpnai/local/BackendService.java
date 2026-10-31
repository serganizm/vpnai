package com.vpnai.local;

import android.app.*;
import android.content.*;
import android.os.*;
import com.chaquo.python.*;
import com.chaquo.python.android.AndroidPlatform;
import java.io.*;
import java.nio.file.*;

public class BackendService extends Service {
    static volatile String url;
    static volatile String error;
    static volatile boolean starting;
    private PowerManager.WakeLock wakeLock;
    private final Handler timer = new Handler(Looper.getMainLooper());
    private PyObject runtime;
    private final Runnable monitor = new Runnable() {
        @Override public void run() {
            if (runtime != null) {
                try {
                    if (!runtime.callAttr("running").toBoolean()) { stopSelf(); return; }
                    boolean busy = runtime.callAttr("busy").toBoolean();
                    if (busy && !wakeLock.isHeld()) wakeLock.acquire(10 * 60 * 1000L);
                    if (!busy && wakeLock.isHeld()) wakeLock.release();
                } catch (Exception ignored) { }
            }
            timer.postDelayed(this, 3000);
        }
    };

    @Override public void onCreate() {
        super.onCreate();
        starting = true; url = null; error = null;
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (Build.VERSION.SDK_INT >= 26) manager.createNotificationChannel(new NotificationChannel("session", "Сеанс VPNAI", NotificationManager.IMPORTANCE_LOW));
        PendingIntent open = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        Notification.Builder builder = Build.VERSION.SDK_INT >= 26 ? new Notification.Builder(this, "session") : new Notification.Builder(this);
        startForeground(1, builder.setSmallIcon(R.drawable.ic_notification).setContentTitle("VPNAI работает на телефоне")
            .setContentText("SSH-сеанс активен. Завершить можно в приложении.")
            .setContentIntent(open).setOngoing(true).build());
        wakeLock = ((PowerManager)getSystemService(POWER_SERVICE)).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "VPNAI:operation");
        new Thread(() -> {
            try {
                File bundle = new File(getFilesDir(), "payload.zip");
                try (InputStream in = getAssets().open("payload.zip"); OutputStream out = new FileOutputStream(bundle)) {
                    byte[] buffer = new byte[32768]; int length;
                    while ((length = in.read(buffer)) != -1) out.write(buffer, 0, length);
                }
                if (!Python.isStarted()) Python.start(new AndroidPlatform(getApplicationContext()));
                runtime = Python.getInstance().getModule("android_runtime");
                url = runtime.callAttr("start", getFilesDir().getAbsolutePath(), bundle.getAbsolutePath()).toString();
                timer.post(monitor);
            } catch (Throwable e) {
                error = "Не удалось запустить VPNAI: " + e.getMessage();
                stopSelf();
            } finally { starting = false; }
        }, "vpnai-start").start();
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) { return START_NOT_STICKY; }
    @Override public IBinder onBind(Intent intent) { return null; }
    @Override public void onDestroy() {
        timer.removeCallbacksAndMessages(null);
        if (wakeLock != null && wakeLock.isHeld()) wakeLock.release();
        url = null;
        // No credentials are serialized; a process killed by Android starts a new session.
        if (runtime != null) new Thread(() -> { try { runtime.callAttr("stop"); } catch (Exception ignored) { } }).start();
        super.onDestroy();
    }
}
