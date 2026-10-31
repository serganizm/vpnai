package com.vpnai.local;

import android.Manifest;
import android.app.*;
import android.content.*;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.net.Uri;
import android.os.*;
import android.util.Base64;
import android.view.*;
import android.webkit.*;
import android.widget.*;
import java.io.*;

public class MainActivity extends Activity {
    private WebView web;
    private TextView status;
    private String loadedUrl;
    private final Handler timer = new Handler(Looper.getMainLooper());
    private ValueCallback<Uri[]> fileCallback;
    private byte[] pendingExport;
    volatile Uri lastExportUri;
    volatile String lastExportError;
    private final Runnable waitForServer = new Runnable() {
        @Override public void run() {
            if (BackendService.error != null) {
                status.setText(BackendService.error + "\n\nЗакройте приложение и попробуйте снова.");
                status.setVisibility(View.VISIBLE); return;
            }
            if (BackendService.url != null && loadedUrl == null) {
                loadedUrl = BackendService.url;
                web.loadUrl(loadedUrl);
                return;
            }
            timer.postDelayed(this, 400);
        }
    };

    @Override public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setStatusBarColor(Color.rgb(16,18,27));
        getWindow().setNavigationBarColor(Color.rgb(16,18,27));
        FrameLayout layout = new FrameLayout(this);
        web = new WebView(this);
        web.setBackgroundColor(Color.rgb(16,18,27));
        layout.addView(web, new FrameLayout.LayoutParams(-1, -1));
        status = new TextView(this);
        status.setText("Запуск VPNAI…\nПервый запуск может занять немного больше времени.");
        status.setTextSize(18); status.setTextColor(Color.rgb(195,161,255));
        status.setBackgroundColor(Color.rgb(16,18,27)); status.setPadding(24,48,24,24);
        layout.addView(status, new FrameLayout.LayoutParams(-1,-1));
        // Android 15 draws edge-to-edge; keep the web app out of system bars.
        layout.setOnApplyWindowInsetsListener((v, insets) -> {
            if (Build.VERSION.SDK_INT >= 30) {
                android.graphics.Insets bars = insets.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
                v.setPadding(bars.left,bars.top,bars.right,bars.bottom);
            } else v.setPadding(insets.getSystemWindowInsetLeft(),insets.getSystemWindowInsetTop(),insets.getSystemWindowInsetRight(),insets.getSystemWindowInsetBottom());
            return insets;
        });
        setContentView(layout);
        WebSettings settings = web.getSettings();
        settings.setJavaScriptEnabled(true); settings.setDomStorageEnabled(true);
        settings.setAllowFileAccess(false); settings.setAllowContentAccess(true);
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        settings.setCacheMode(WebSettings.LOAD_NO_CACHE);
        CookieManager.getInstance().setAcceptThirdPartyCookies(web, false);
        web.addJavascriptInterface(new ExportBridge(), "VPNAIAndroid");
        web.setWebViewClient(new WebViewClient() {
            @Override public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                Uri uri = request.getUrl();
                if (isLocal(uri)) return false;
                if ("https".equals(uri.getScheme())) {
                    try { startActivity(new Intent(Intent.ACTION_VIEW, uri)); }
                    catch (ActivityNotFoundException e) { toast("Не найден браузер для открытия ссылки."); }
                }
                return true;
            }
            @Override public void onPageFinished(WebView view, String url) {
                if (isLocal(Uri.parse(url))) status.setVisibility(View.GONE);
            }
            @Override public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
                if (request.isForMainFrame()) { status.setText("Нет связи с локальным приложением.\n" + error.getDescription()); status.setVisibility(View.VISIBLE); }
            }
        });
        web.setWebChromeClient(new WebChromeClient() {
            @Override public boolean onShowFileChooser(WebView view, ValueCallback<Uri[]> callback, FileChooserParams params) {
                if (fileCallback != null) fileCallback.onReceiveValue(null);
                fileCallback = callback;
                Intent pick = new Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*");
                try { startActivityForResult(pick, 100); return true; }
                catch (ActivityNotFoundException e) { fileCallback = null; return false; }
            }
        });
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED)
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 102);
        Intent service = new Intent(this, BackendService.class);
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(service); else startService(service);
        timer.post(waitForServer);
    }

    private boolean isLocal(Uri uri) {
        String serviceUrl = BackendService.url;
        if (serviceUrl == null) return false;
        Uri base = Uri.parse(serviceUrl);
        return "http".equals(uri.getScheme()) && "127.0.0.1".equals(uri.getHost()) && uri.getPort() == base.getPort();
    }

    private void toast(String text) { Toast.makeText(this,text,Toast.LENGTH_LONG).show(); }

    private class ExportBridge {
        @JavascriptInterface public void sessionEnded() {
            runOnUiThread(() -> { if (web.getUrl() != null && isLocal(Uri.parse(web.getUrl()))) finishAndRemoveTask(); });
        }
        @JavascriptInterface public void saveFile(String filename, String mime, String encoded) {
            if (encoded == null || encoded.length() > 90 * 1024 * 1024) { runOnUiThread(() -> toast("Файл слишком большой для сохранения.")); return; }
            byte[] bytes;
            try { bytes = Base64.decode(encoded, Base64.DEFAULT); }
            catch (IllegalArgumentException e) { return; }
            runOnUiThread(() -> {
                if (pendingExport != null) { toast("Сначала завершите сохранение предыдущего файла."); return; }
                if (!isLocal(Uri.parse(web.getUrl()))) return;
                pendingExport = bytes;
                lastExportUri = null; lastExportError = null;
                Intent save = new Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE)
                    .setType(mime == null || mime.isEmpty() ? "application/octet-stream" : mime)
                    .putExtra(Intent.EXTRA_TITLE, filename.replaceAll("[\\\\/\\p{Cntrl}]", "_"));
                try { startActivityForResult(save, 101); }
                catch (ActivityNotFoundException e) { pendingExport = null; toast("Не удалось открыть выбор папки."); }
            });
        }
    }

    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request,result,data);
        if (request == 100 && fileCallback != null) {
            fileCallback.onReceiveValue(result == RESULT_OK && data != null && data.getData() != null ? new Uri[]{data.getData()} : null); fileCallback = null;
        }
        if (request == 101) {
            byte[] bytes = pendingExport; pendingExport = null;
            if (result == RESULT_OK && data != null && data.getData() != null && bytes != null) {
                Uri uri = data.getData();
                new Thread(() -> {
                    try {
                        try (OutputStream out = getContentResolver().openOutputStream(uri)) {
                            if (out == null) throw new IOException("No output stream");
                            out.write(bytes);
                        }
                        lastExportUri = uri;
                        runOnUiThread(() -> toast("Файл сохранён."));
                    } catch (Exception e) { lastExportError = e.toString(); runOnUiThread(() -> toast("Не удалось сохранить файл.")); }
                }).start();
            }
        }
    }

    @Override public void onBackPressed() {
        if (web.canGoBack()) { web.goBack(); return; }
        new AlertDialog.Builder(this).setTitle("Свернуть VPNAI?")
            .setMessage("Подключения и текущая операция останутся активными. Для завершения сеанса используйте «Выйти» в приложении.")
            .setPositiveButton("Свернуть",(d,w) -> moveTaskToBack(true)).setNegativeButton("Остаться",null).show();
    }
    @Override protected void onDestroy() {
        timer.removeCallbacksAndMessages(null);
        if (fileCallback != null) fileCallback.onReceiveValue(null);
        pendingExport = null;
        web.removeJavascriptInterface("VPNAIAndroid"); web.destroy();
        super.onDestroy();
    }
}
