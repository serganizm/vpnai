package com.vpnai.local;

import android.app.*;
import android.content.*;
import android.os.*;
import android.webkit.WebView;
import android.view.*;
import java.util.concurrent.*;
import com.chaquo.python.*;

/** Installed-device smoke check: native crypto, bundled payload, local API and WebView. */
public class SmokeInstrumentation extends Instrumentation {
    @Override public void onCreate(Bundle arguments) { super.onCreate(arguments); start(); }
    @Override public void onStart() {
        Bundle result = new Bundle();
        try {
            Intent intent = new Intent(getTargetContext(), MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            Activity activity = startActivitySync(intent);
            long deadline = System.currentTimeMillis() + 120000;
            while (BackendService.url == null && BackendService.error == null && System.currentTimeMillis() < deadline) Thread.sleep(250);
            if (BackendService.error != null) throw new AssertionError(BackendService.error);
            if (BackendService.url == null) throw new AssertionError("Backend startup timed out");
            String checks = Python.getInstance().getModule("android_runtime").callAttr("offline_check").toString();
            String[] page = {null};
            for (int i = 0; i < 50; i++) {
                CountDownLatch latch = new CountDownLatch(1);
                runOnMainSync(() -> {
                    WebView web = findWebView(activity.getWindow().getDecorView());
                    web.evaluateJavascript("({ready:document.readyState, title:document.title, bridge:typeof VPNAIAndroid.saveFile, save:typeof vpnaiSaveBlob, formsReady:!!document.querySelector('[data-admin-action=connect]') && !document.querySelector('[data-admin-action=connect]').disabled, bodyWidth:document.body.scrollWidth, width:innerWidth})", value -> {page[0] = value; latch.countDown();});
                });
                latch.await(5, TimeUnit.SECONDS);
                if (page[0] != null && page[0].contains("complete") && page[0].contains("\"formsReady\":true")) break;
                Thread.sleep(300);
            }
            if (page[0] == null || !page[0].contains("complete") || !page[0].contains("function") || !page[0].contains("\"formsReady\":true")) throw new AssertionError("WebView did not load app: " + page[0]);
            runOnMainSync(() -> findWebView(activity.getWindow().getDecorView()).evaluateJavascript("vpnaiSaveBlob(new Blob(['VPNAI Android export smoke test\\n'],{type:'text/plain'}),'vpnai-export-smoke.txt')", null));
            boolean saved = false;
            for (int i = 0; i < 60 && !saved; i++) {
                Thread.sleep(250);
                android.view.accessibility.AccessibilityNodeInfo root = getUiAutomation().getRootInActiveWindow();
                if (root == null || root.getPackageName() == null || !root.getPackageName().toString().contains("documentsui")) continue;
                for (android.view.accessibility.AccessibilityNodeInfo node : root.findAccessibilityNodeInfosByText("Save")) {
                    if (node.isClickable() && node.isEnabled() && node.performAction(android.view.accessibility.AccessibilityNodeInfo.ACTION_CLICK)) { saved = true; break; }
                }
            }
            if (!saved) throw new AssertionError("Android document save picker did not open");
            MainActivity main = (MainActivity)activity;
            for (int i=0; i<100 && main.lastExportUri == null && main.lastExportError == null; i++) Thread.sleep(100);
            if (main.lastExportError != null) throw new AssertionError(main.lastExportError);
            if (main.lastExportUri == null) throw new AssertionError("Export did not finish");
            try (java.io.InputStream stream = main.getContentResolver().openInputStream(main.lastExportUri)) {
                byte[] bytes = new byte[256]; int count = stream.read(bytes);
                if (count < 1 || !new String(bytes,0,count,java.nio.charset.StandardCharsets.UTF_8).equals("VPNAI Android export smoke test\n")) throw new AssertionError("Saved file contents differ");
            }
            String previous = BackendService.url;
            Python.getInstance().getModule("android_runtime").callAttr("stop");
            for (int i=0; i<100 && BackendService.url != null; i++) Thread.sleep(100);
            if (BackendService.url != null) throw new AssertionError("Service did not stop after session ended");
            runOnMainSync(() -> main.finishAndRemoveTask());
            Activity reopened = startActivitySync(intent);
            for (int i=0; i<100 && BackendService.url == null && BackendService.error == null; i++) Thread.sleep(100);
            if (BackendService.url == null || previous.equals(BackendService.url)) throw new AssertionError("Fresh session did not start");
            for (int i=0; i<50 && !reopened.isFinishing(); i++) {
                runOnMainSync(() -> { if (!reopened.isFinishing()) findWebView(reopened.getWindow().getDecorView()).evaluateJavascript("if(typeof vpnaiSaveBlob==='function') window.dispatchEvent(new Event('vpnai-session-ended'))", null); });
                Thread.sleep(200);
            }
            if (!reopened.isFinishing()) throw new AssertionError("Exit event did not close Android activity");
            Python.getInstance().getModule("android_runtime").callAttr("stop");
            result.putString("stream", "\nVPNAI Android smoke test passed\n" + checks + "\nWebView: " + page[0] + "\nAndroid document export: saved and read back successfully\nSession restart: new token, service stopped and restarted\nExit event: closes Android activity\n");
            finish(Activity.RESULT_OK, result);
        } catch (Throwable error) {
            result.putString("stream", "\nFAILED: " + error + "\n");
            finish(Activity.RESULT_CANCELED, result);
        }
    }
    private WebView findWebView(View view) {
        if (view instanceof WebView) return (WebView)view;
        if (view instanceof ViewGroup) for (int i=0; i<((ViewGroup)view).getChildCount(); i++) {
            WebView result = findWebView(((ViewGroup)view).getChildAt(i)); if (result != null) return result;
        }
        return null;
    }
}
