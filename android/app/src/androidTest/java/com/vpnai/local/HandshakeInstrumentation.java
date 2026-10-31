package com.vpnai.local;

import android.app.*;
import android.content.*;
import android.os.*;
import com.chaquo.python.*;

/** Opt-in network diagnostic: host key negotiation only; never authenticates. */
public class HandshakeInstrumentation extends Instrumentation {
    private String host;
    @Override public void onCreate(Bundle arguments) {
        host = arguments.getString("host");
        super.onCreate(arguments); start();
    }
    @Override public void onStart() {
        Bundle result = new Bundle();
        try {
            if (host == null || !host.matches("[0-9.]+")) throw new IllegalArgumentException("Pass an IPv4 host explicitly");
            startActivitySync(new Intent(getTargetContext(), MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
            long deadline = System.currentTimeMillis() + 120000;
            while (BackendService.url == null && BackendService.error == null && System.currentTimeMillis() < deadline) Thread.sleep(200);
            if (BackendService.url == null) throw new AssertionError("Startup failed: " + BackendService.error);
            PyObject scope = Python.getInstance().getModule("builtins").callAttr("dict");
            scope.callAttr("__setitem__", "host", host);
            String probe = "import socket,paramiko,json,io,logging,traceback\n" +
                "log=io.StringIO()\nhandler=logging.StreamHandler(log)\nlogging.getLogger('paramiko').addHandler(handler)\n" +
                "sock=transport=None\nresult={'host':host,'authenticated':False,'commands_run':False}\n" +
                "try:\n sock=socket.create_connection((host,22),timeout=12)\n transport=paramiko.Transport(sock)\n transport.banner_timeout=20\n transport.start_client(timeout=20)\n key=transport.get_remote_server_key()\n result.update(connected=True,banner=transport.remote_version,key_type=key.get_name())\n" +
                "except Exception as error:\n result.update(connected=False,error=repr(error),traceback=traceback.format_exc(),ssh_log=log.getvalue())\n" +
                "finally:\n logging.getLogger('paramiko').removeHandler(handler)\n if transport:transport.close()\n if sock:sock.close()\n" +
                "output=json.dumps(result)\n";
            Python.getInstance().getModule("builtins").callAttr("exec", probe, scope);
            result.putString("stream", "\n" + scope.get("output").toString() + "\n");
            finish(Activity.RESULT_OK, result);
        } catch (Throwable error) {
            result.putString("stream", "\nFAILED: " + error + "\n");
            finish(Activity.RESULT_CANCELED, result);
        }
    }
}
